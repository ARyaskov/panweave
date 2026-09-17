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

/// The dispatcher with every layer-executed cluster: arbitrary frames,
/// deliveries and timer advances never panic (mirrors the `zcl_dispatch`
/// fuzz target).
fn drive_dispatcher(data: &[u8]) {
    use panweave_aps::layer::{DataIndication, Delivery, SecurityStatus};
    use panweave_aps::tables::GroupTable;
    use panweave_types::time::{Duration, Instant};
    use panweave_types::{ClusterId, Endpoint, GroupAddress, ProfileId, ShortAddress};
    use panweave_zcl::clusters::{basic, groups, identify, level, on_off, poll_control, scenes};
    use panweave_zcl::layer::{EndpointInstance, Zcl};

    let mut zcl: Zcl<1, 8, 16> = Zcl::new();
    let mut ep = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
    ep.add_instance(basic::server(1, b"test", b"test").unwrap())
        .unwrap();
    ep.add_instance(identify::server().unwrap()).unwrap();
    ep.add_instance(groups::server().unwrap()).unwrap();
    ep.add_instance(scenes::server().unwrap()).unwrap();
    ep.add_instance(on_off::server().unwrap()).unwrap();
    ep.add_instance(level::server(1, 254).unwrap()).unwrap();
    ep.add_instance(poll_control::server(2, 4, 480).unwrap())
        .unwrap();
    zcl.add_endpoint(ep).unwrap();
    let mut groups = GroupTable::<4>::new();
    groups.add(GroupAddress(1), Endpoint(1)).unwrap();
    let mut now = Instant::from_millis(1000);
    zcl.poll_timers(now);
    for chunk in data.chunks(24) {
        let Some((&ctl, frame)) = chunk.split_first() else {
            break;
        };
        let cluster = match ctl & 0x07 {
            0 => basic::ID,
            1 => identify::ID,
            2 => groups::ID,
            3 => scenes::ID,
            4 => on_off::ID,
            5 => level::ID,
            6 => poll_control::ID,
            _ => ClusterId(0x0402),
        };
        let delivery = match (ctl >> 3) & 0x03 {
            0 => Delivery::Endpoint(Endpoint(1)),
            1 => Delivery::Group(GroupAddress(1)),
            2 => Delivery::AllEndpoints,
            _ => Delivery::Endpoint(Endpoint(7)),
        };
        let ind = DataIndication {
            src: ShortAddress(0x1234),
            src_endpoint: Endpoint(5),
            src_ieee: None,
            delivery,
            profile: ProfileId::HOME_AUTOMATION,
            cluster,
            asdu: frame,
            security: if ctl & 0x20 != 0 {
                SecurityStatus::LinkKey
            } else {
                SecurityStatus::NwkKey
            },
            lqi: 200,
            relayed: None,
            counter: 0,
            nwk_broadcast: ctl & 0x40 != 0,
        };
        let _ = zcl.on_data(&ind, &mut groups);
        while zcl.next_action().is_some() {}
        while zcl.next_event().is_some() {}
        now += Duration::from_millis(u64::from(ctl >> 5) * 100 + 1);
        zcl.poll_timers(now);
        let _ = zcl.next_deadline();
    }
    for _ in 0..64 {
        now += Duration::from_millis(250);
        zcl.poll_timers(now);
        while zcl.next_action().is_some() {}
        while zcl.next_event().is_some() {}
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]
    #[test]
    fn dispatcher_is_total(data in proptest::collection::vec(any::<u8>(), 0..200)) {
        drive_dispatcher(&data);
    }
}
