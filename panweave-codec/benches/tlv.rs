//! Annex I TLV validation and iteration over a realistic beacon appendix
//! (Supported Key Negotiation Methods, Router Information, Fragmentation
//! Parameters).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use panweave_codec::tlv::TlvSet;
use std::hint::black_box;

// tag, length - 1, value…
const APPENDIX: &[u8] = &[
    // Supported Key Negotiation Methods: protocols, secrets, source IEEE.
    0x41, 0x09, 0x01, 0x03, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00, 0x00, //
    // Router Information.
    0x45, 0x01, 0x03, 0x00, //
    // Fragmentation Parameters: node, options, MTU.
    0x46, 0x04, 0x34, 0x12, 0x00, 0x52, 0x00, //
];

fn tlv(c: &mut Criterion) {
    let mut group = c.benchmark_group("tlv");
    group.throughput(Throughput::Bytes(APPENDIX.len() as u64));
    group.bench_function("validate", |b| {
        b.iter(|| {
            TlvSet::validate(black_box(APPENDIX), |_| false)
                .map(|s| s.iter().count())
                .unwrap()
        });
    });
    group.bench_function("find", |b| {
        let set = TlvSet::validate(APPENDIX, |_| false).unwrap();
        b.iter(|| black_box(&set).find(black_box(0x46)).map(|t| t.value.len()));
    });
    group.finish();
}

criterion_group!(benches, tlv);
criterion_main!(benches);
