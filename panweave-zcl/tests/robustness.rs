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

#[path = "support/dispatcher.rs"]
mod dispatcher;

#[test]
fn dispatcher_harness_reaches_every_server_and_full_length_frames() {
    for (index, expected) in dispatcher::CLUSTERS.iter().enumerate() {
        let selector = u8::try_from(index).unwrap();
        let mut input = vec![selector, 0, 0];
        input.extend_from_slice(&[0x01, 0, 0]);
        input.resize(259, 0);
        let (cluster, frames, max_length, _) = dispatcher::drive(&input);
        assert_eq!(cluster, *expected);
        assert_eq!(frames, 1);
        assert_eq!(max_length, 256);
    }
}

#[test]
fn dispatcher_harness_executes_a_long_weekly_schedule() {
    let mut frame = vec![0x01, 0, 0x01, 4, 1, 3];
    for minute in [0u16, 360, 720, 1080] {
        frame.extend_from_slice(&minute.to_le_bytes());
        frame.extend_from_slice(&2000i16.to_le_bytes());
        frame.extend_from_slice(&2600i16.to_le_bytes());
    }
    assert!(frame.len() > 23);
    let mut input = vec![8, 0, u8::try_from(frame.len()).unwrap()];
    input.extend_from_slice(&frame);
    let (_, frames, max_length, schedules) = dispatcher::drive(&input);
    assert_eq!(frames, 1);
    assert_eq!(max_length, frame.len());
    assert_eq!(schedules, 1);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]
    #[test]
    fn dispatcher_is_total(data in proptest::collection::vec(any::<u8>(), 0..600)) {
        let _ = dispatcher::drive(&data);
    }
}
