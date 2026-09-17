//! Property tests: ZDP decoding never panics.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_codec::Decode;
use panweave_zdo::descriptor::{NodeDescriptor, PowerDescriptor, SimpleDescriptor};
use panweave_zdo::zdp::*;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]
    #[test]
    fn zdp_decoding_is_total(data in proptest::collection::vec(any::<u8>(), 0..90)) {
        let _ = ZdpFrame::decode_exact(&data);
        let _ = NwkAddrReq::decode_exact(&data);
        let _ = AddrRsp::decode_exact(&data);
        let _ = NodeDescRsp::decode_exact(&data);
        let _ = PowerDescRsp::decode_exact(&data);
        if let Ok(r) = SimpleDescRsp::decode_exact(&data) {
            let _ = r.descriptor.map(SimpleDescriptor::decode_exact);
        }
        let _ = EndpointListRsp::decode_exact(&data);
        let _ = MatchDescReq::decode_exact(&data);
        let _ = ParentAnnce::decode_exact(&data);
        let _ = BindReq::decode_exact(&data);
        if let Ok(r) = ClearAllBindingsReq::decode_exact(&data) {
            let _ = r.eui64s().map(|l| l.iter().count());
        }
        let _ = MgmtNwkUpdateReq::decode_exact(&data);
        if let Ok(t) = TableRsp::decode_exact(&data) {
            for r in t.iter::<NeighborRecord>() {
                let _ = r;
            }
            for r in t.iter::<BindReq>() {
                let _ = r;
            }
        }
        let _ = NodeDescriptor::decode_exact(&data);
        let _ = PowerDescriptor::decode_exact(&data);
        let _ = SimpleDescriptor::decode_exact(&data);
    }
}
