//! NWK header / frame codec: the per-hop cost of parsing and rebuilding a
//! routed data frame with and without the source IEEE address.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use panweave_codec::{Decode, Encode};
use panweave_nwk::frame::{Frame, FrameType, Header};
use panweave_types::{ExtendedAddress, ShortAddress};
use std::hint::black_box;

fn encoded(with_ieee: bool) -> Vec<u8> {
    let mut header = Header::new(
        FrameType::Data,
        ShortAddress(0x1234),
        ShortAddress(0x0000),
        30,
        77,
    )
    .secured(true);
    if with_ieee {
        header = header.with_src_ieee(ExtendedAddress(0x00AA_0000_0000_0001));
    }
    let payload = [0x5Au8; 64];
    let frame = Frame {
        header,
        payload: &payload,
    };
    let mut buf = vec![0u8; 128];
    let n = frame.encode_to_slice(&mut buf).unwrap();
    buf.truncate(n);
    buf
}

fn nwk_frame(c: &mut Criterion) {
    let mut group = c.benchmark_group("nwk-frame");
    for (name, with_ieee) in [("short", false), ("src-ieee", true)] {
        let bytes = encoded(with_ieee);
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_function(format!("decode/{name}"), |b| {
            b.iter(|| {
                Frame::decode_exact(black_box(&bytes))
                    .unwrap()
                    .payload
                    .len()
            });
        });
        group.bench_function(format!("encode/{name}"), |b| {
            let frame = Frame::decode_exact(&bytes).unwrap();
            let mut out = [0u8; 128];
            b.iter(|| black_box(&frame).encode_to_slice(&mut out).unwrap());
        });
    }
    group.finish();
}

criterion_group!(benches, nwk_frame);
criterion_main!(benches);
