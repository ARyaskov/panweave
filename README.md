# Panweave

Panweave is an independent, open-source Rust implementation of
IEEE 802.15.4-based Zigbee protocol functionality for embedded and host-side
systems.

* Rust 1.95, edition 2024, stable only.
* `no_std` by default; optional `alloc` and `std`.
* Targets microcontrollers (ESP32-C6/H2, nRF52/nRF54, EFR32, generic
  802.15.4 radios) and host coordinators using an external 802.15.4 RCP.
* Coordinator, Router, End Device and Sleepy End Device roles.
* Layers: MAC abstraction, NWK, security, APS, ZDO/ZDP, ZCL, BDB 3.1,
  Device Type Library, plus optional Green Power, Zigbee Direct and
  Smart Energy subsystems.
* Deterministic simulation (`panweave-sim`), fuzzing, PCAP tooling.

Panweave is not affiliated with, sponsored by, endorsed by, or certified by
the Connectivity Standards Alliance. It is implemented from the published
specifications listed in `specification/README.md`.

## Status

Early development (`0.x`). `docs/conformance.md` is the only authoritative
statement of what is implemented; compiling code is not a claim of
conformance.

Milestone 1 is reached: `panweave-runtime/tests/milestone1.rs` runs a
virtual coordinator and a virtual end device through the real MAC, NWK,
APS, ZDO and ZCL layers over a virtual radio with virtual time — network
formation, discovery, Network Commissioning join, Trust Center
authorization (network key and unique link key), device announce, ZDO
interview and ZCL attribute reads, commands and reports.

Milestone 2 is reached: `panweave-runtime/tests/milestone2.rs` adds a
virtual router and a sleepy end device — multi-hop routing, MAC polling
with indirect delivery, the network key tunnelled through the parent,
bindings and attribute reports across the router, and a secured rejoin to
the coordinator after the router fails.

## Layout

See `docs/architecture.md`. Quick tour:

| Path | Purpose |
|---|---|
| `panweave/` | Facade crate with `Coordinator`, `Router`, `EndDevice` builders |
| `panweave-types/`, `panweave-codec/` | Core types and bounded codec |
| `panweave-mac/` | 802.15.4 radio/MAC abstraction and frame codec |
| `panweave-nwk/`, `panweave-security/`, `panweave-aps/`, `panweave-zdo/`, `panweave-zcl/` | Protocol layers |
| `panweave-bdb/`, `panweave-device-library/` | Commissioning and device types |
| `panweave-green-power/`, `panweave-direct/`, `panweave-smart-energy/` | Optional subsystems |
| `panweave-storage/`, `panweave-runtime/` | Persistence and stack driver |
| `panweave-testkit/`, `panweave-sim/`, `panweave-pcap/`, `panweave-cli/` | Testing, simulation and host tooling |
| `conformance/`, `docs/` | Requirement inventory and documentation |

## Building

```bash
cargo check --workspace --all-targets
cargo test --workspace
cargo xtask gate      # fmt, clippy, tests, no_std builds, conformance
```

## License

Dual-licensed under MIT or Apache-2.0, at your option.
