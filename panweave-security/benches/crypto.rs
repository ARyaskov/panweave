//! CCM* and AES-MMO throughput with the software AES backend: the cost of
//! securing / unsecuring a full-size NWK frame and of hashing an install
//! code.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use panweave_security::ccm::{decrypt_in_place, encrypt_in_place};
use panweave_security::cipher::{BlockCipher, SoftwareAes};
use panweave_security::mmo;
use panweave_types::Key128;
use std::hint::black_box;

const NONCE: [u8; 13] = [
    0xAC, 0xDE, 0x48, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x02, 0x01, 0x06, 0x05,
];

fn ccm(c: &mut Criterion) {
    let cipher = SoftwareAes::new(&Key128::from_bytes([0x5A; 16]));
    let aad = [0x11u8; 22];
    let mut group = c.benchmark_group("ccm-star");
    for &len in &[16usize, 64, 96] {
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_function(format!("encrypt-mic32/{len}B"), |b| {
            let mut msg = vec![0x42u8; len];
            let mut mic = [0u8; 4];
            b.iter(|| {
                encrypt_in_place(
                    black_box(&cipher),
                    black_box(&NONCE),
                    black_box(&aad),
                    &mut msg,
                    &mut mic,
                )
                .unwrap();
            });
        });
        group.bench_function(format!("decrypt-mic32/{len}B"), |b| {
            let mut plain = vec![0x42u8; len];
            let mut mic = [0u8; 4];
            encrypt_in_place(&cipher, &NONCE, &aad, &mut plain, &mut mic).unwrap();
            let sealed = plain;
            b.iter(|| {
                let mut msg = sealed.clone();
                decrypt_in_place(
                    black_box(&cipher),
                    black_box(&NONCE),
                    black_box(&aad),
                    &mut msg,
                    &mic,
                )
                .unwrap();
            });
        });
    }
    group.finish();
}

fn aes_mmo(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes-mmo");
    for &len in &[18usize, 64, 128] {
        group.throughput(Throughput::Bytes(len as u64));
        let data = vec![0x33u8; len];
        group.bench_function(format!("hash/{len}B"), |b| {
            b.iter(|| mmo::hash::<SoftwareAes>(black_box(&data)));
        });
    }
    group.bench_function("hmac/16B", |b| {
        let key = [0x77u8; 16];
        let data = [0x22u8; 16];
        b.iter(|| mmo::hmac::<SoftwareAes>(black_box(&key), black_box(&data)));
    });
    group.finish();
}

criterion_group!(benches, ccm, aes_mmo);
criterion_main!(benches);
