//! ZDP request/response decoding never panics.
#![no_main]
use libfuzzer_sys::fuzz_target;
use panweave_codec::Decode;
use panweave_zdo::descriptor::{NodeDescriptor, PowerDescriptor, SimpleDescriptor};
use panweave_zdo::zdp::*;

fuzz_target!(|data: &[u8]| {
    let _ = ZdpFrame::decode_exact(data);
    let _ = NwkAddrReq::decode_exact(data);
    let _ = IeeeAddrReq::decode_exact(data);
    let _ = AddrRsp::decode_exact(data);
    let _ = NodeDescReq::decode_exact(data);
    let _ = NodeDescRsp::decode_exact(data);
    let _ = PowerDescRsp::decode_exact(data);
    if let Ok(r) = SimpleDescRsp::decode_exact(data) {
        let _ = r.descriptor.map(SimpleDescriptor::decode_exact);
    }
    let _ = EndpointListRsp::decode_exact(data);
    let _ = MatchDescReq::decode_exact(data);
    let _ = DeviceAnnce::decode_exact(data);
    let _ = ParentAnnce::decode_exact(data);
    let _ = ParentAnnceRsp::decode_exact(data);
    let _ = BindReq::decode_exact(data);
    if let Ok(r) = ClearAllBindingsReq::decode_exact(data) {
        let _ = r.eui64s().map(|l| l.iter().count());
    }
    let _ = MgmtLeaveReq::decode_exact(data);
    let _ = MgmtPermitJoiningReq::decode_exact(data);
    let _ = MgmtNwkUpdateReq::decode_exact(data);
    let _ = MgmtNwkUpdateNotify::decode_exact(data);
    if let Ok(t) = TableRsp::decode_exact(data) {
        for r in t.iter::<NeighborRecord>() {
            let _ = r;
        }
        for r in t.iter::<RouteRecord>() {
            let _ = r;
        }
        for r in t.iter::<BindReq>() {
            let _ = r;
        }
    }
    let _ = NodeDescriptor::decode_exact(data);
    let _ = PowerDescriptor::decode_exact(data);
    let _ = SimpleDescriptor::decode_exact(data);
});
