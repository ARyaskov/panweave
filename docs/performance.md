# Performance

Criterion benchmarks live next to the crates they measure; none of them
allocate in the measured path, and all of them run the same code the
`no_std` build ships.

| Bench | Command | What it measures |
|---|---|---|
| `crypto` | `cargo bench -p panweave-security --bench crypto` | CCM* (MIC-32) encrypt / decrypt of 16–96 B payloads with 22 B of associated data, AES-MMO hashing and HMAC, software AES |
| `tlv` | `cargo bench -p panweave-codec --bench tlv` | Annex I TLV validation and lookup of a beacon appendix |
| `frame` | `cargo bench -p panweave-nwk --bench frame` | NWK header / frame decode and encode with and without the source IEEE address |
| `dispatch` | `cargo bench -p panweave-zcl --bench dispatch` | Read Attributes served from the attribute store, an On/Off Toggle and a Level Control command executed by the dispatcher, the idle timer scan |

Indicative numbers from a desktop x86-64 build (`cargo bench`, software
AES; an MCU with a hardware AES block will differ by orders of magnitude on
the crypto rows and roughly by the clock ratio elsewhere):

| Operation | Time |
|---|---|
| CCM* encrypt, 64 B payload, MIC-32 | ≈ 0.2 µs |
| CCM* decrypt, 64 B payload, MIC-32 | ≈ 0.25 µs |
| AES-MMO hash, 18 B install code | ≈ 0.27 µs |
| TLV validate, 3-TLV beacon appendix | ≈ 15 ns |
| NWK frame decode / encode | ≈ 31–37 ns |
| ZCL Read Attributes (3 attributes) | ≈ 0.2 µs |
| ZCL On/Off Toggle (with Level Control fade set-up and scene bookkeeping) | ≈ 0.44 µs |
| ZCL idle `poll_timers` (6 clusters) | ≈ 66 ns |

The numbers are not tracked in CI; `cargo check --workspace --all-targets`
(part of the gate) keeps the benches compiling.

## Fuzzing

`fuzz/` holds the libFuzzer targets (`cargo install cargo-fuzz`, then
`cargo fuzz run <target>`): the MAC, NWK, APS, ZDP, ZCL and TLV codecs, the
secured-frame path, the MAC service, APS reception, the ZDP security
services (`zdp_security`) and the ZCL endpoint dispatcher with every
layer-executed cluster (`zcl_dispatch`). CI builds every target and runs
each for 20 s; the proptest suites (`*/tests/robustness.rs`) mirror the
codec and dispatcher targets so that the same properties are checked by
`cargo test`.
