# Panweave architecture

Panweave is a layered, hardware-independent Rust implementation of the
Zigbee protocol family. This document explains the crate decomposition, the
data flow between layers, the concurrency and timing model, and the
conventions every crate follows.

## Crate map

```
                 ┌──────────────────────────────────────────────┐
  applications   │ panweave  (Coordinator / Router / EndDevice) │
                 └───────┬──────────────┬────────────────┬──────┘
                         │              │                │
        ┌────────────────┴──┐   ┌───────┴───────┐  ┌─────┴───────────┐
        │ panweave-runtime  │   │ panweave-bdb  │  │ device-library  │
        │ (stack driver,    │   │ (commission-  │  │ (device types)  │
        │  endpoints,       │   │  ing state    │  └─────┬───────────┘
        │  event streams)   │   │  machines)    │        │
        └───────┬───────────┘   └───────┬───────┘  ┌─────┴───────────┐
                │                       │          │ panweave-zcl    │
                │   ┌───────────────────┴───┐      │ (foundation,    │
                │   │ panweave-zdo (ZDP+ZDO)│      │  clusters,      │
                │   └───────────┬───────────┘      │  reporting)     │
                │               │                  └─────┬───────────┘
        ┌───────┴───────────────┴────────────────────────┴──────┐
        │ panweave-aps  (APS data/management, binding, groups,   │
        │                fragmentation, acks, APS security cmds) │
        └───────────────────────────┬────────────────────────────┘
                                    │
        ┌───────────────────────────┴────────────────────────────┐
        │ panweave-nwk  (NWK frames, routing, join/leave,        │
        │                neighbor/child mgmt, broadcast, NIB)    │
        └───────────────────────────┬────────────────────────────┘
                                    │
        ┌───────────────────────────┴────────────────────────────┐
        │ panweave-mac  (IEEE 802.15.4 radio/MAC abstraction:    │
        │                traits, frame codec, scan/assoc helpers)│
        └───────────────────────────┬────────────────────────────┘
                                    │
             vendor backends / RCP adapters / panweave-sim radio

  cross-cutting: panweave-types, panweave-codec, panweave-security,
                 panweave-storage, panweave-testkit
  optional:      panweave-green-power, panweave-direct, panweave-smart-energy
  host tooling:  panweave-sim, panweave-pcap, panweave-cli
```

| Crate | Responsibility | `no_std` |
|---|---|---|
| `panweave-types` | Newtypes for protocol identifiers, addresses, keys (redacted `Debug`), status codes, time primitives, capacities. No I/O. | yes |
| `panweave-codec` | `Decode`/`Encode` traits, bounded byte reader/writer, TLV framing, panic-free helpers. | yes |
| `panweave-mac` | Radio/MAC HAL traits (`Radio`, `MacTimer`), 802.15.4 frame codec (header, beacon, association, data), `MacService` state (sequence numbers, pending data, scan helpers). Vendor-independent. | yes |
| `panweave-security` | CCM*, AES-MMO, HMAC, key hierarchy, NWK/APS auxiliary headers, frame-counter windows, Trust Center policy engine, DLK/SPEKE key negotiation, install codes. | yes |
| `panweave-nwk` | NWK frame codec, NIB, neighbor/route/broadcast tables, discovery, formation, join/rejoin/leave, routing, broadcast, end-device aging, link status, PAN-ID conflict, network update. | yes |
| `panweave-aps` | APS frame codec, AIB, ack/retry, fragmentation, duplicate rejection, binding/group tables, APS command processing, inter-PAN. | yes |
| `panweave-zdo` | ZDP request/response codecs, descriptors, ZDO server (responder) and client (requester) state, device interview. | yes |
| `panweave-zcl` | ZCL frame/data types, general commands, attribute store, reporting engine, cluster metadata, generated typed clusters. | yes |
| `panweave-device-library` | Device type metadata, endpoint builders, composition validation. | yes |
| `panweave-bdb` | BDB 3.1 commissioning state machines. | yes |
| `panweave-storage` | Storage traits, transactional record model, frame-counter reservation strategy, in-memory and file backends. | yes (backends may need `std`) |
| `panweave-runtime` | Glue: drives MAC→NWK→APS→ZDO/ZCL, endpoints, timers, event queues, application API for the three roles, sleepy end-device polling. | yes |
| `panweave-green-power` | GPDF codec, GP security, proxy/sink tables, GP cluster. Optional. | yes |
| `panweave-direct` | Zigbee Direct security sessions, commissioning/tunnel services over an abstract BLE transport. Optional. | yes |
| `panweave-smart-energy` | SE clusters, CBKE, SE commissioning/security policy. Optional. | yes |
| `panweave-testkit` | Virtual clock, deterministic RNG, in-memory storage, frame builders, test vectors. | yes (with `std` for host) |
| `panweave-sim` | Multi-node simulator: virtual radio medium, loss/delay/partition models, deterministic scheduling. | `std` |
| `panweave-pcap` | PCAP/PCAPNG read/write of 802.15.4 frames, layered dissection. | `std` |
| `panweave-cli` | Diagnostic CLI. | `std` |
| `panweave` | Facade crate: builders, re-exports, role-specific ergonomic APIs. | yes |

## Layer interfaces

Every protocol layer is a **sans-I/O state machine**:

* it consumes *inputs* (`handle_frame`, `handle_timer`, `request(...)`),
* it produces *actions* (`Action::Transmit`, `Action::StartTimer`,
  `Action::Persist`, `Action::Indicate`) via a bounded output queue,
* it never touches the radio, clock, RNG, or storage directly; those are
  injected by `panweave-runtime`.

This keeps the layers testable without executors and makes the whole stack
deterministic under `panweave-sim`. The runtime owns the async loop:

```rust
loop {
    select! {
        frame = radio.receive() => stack.on_mac_frame(frame),
        _     = timer.expired()  => stack.on_timer(now),
        req   = app.next()       => stack.on_request(req),
    }
    stack.drain_actions(&mut radio, &mut storage, &mut events).await?;
}
```

Applications either call `stack.poll().await` themselves or hand the stack to
a runtime driver (`Coordinator::run`, `EndDevice::run`).

## Frame flow

Receive path:

```
radio bytes ─► mac::Frame<'a> (borrowed) ─► nwk::Frame<'a> (borrowed, security
   header parsed) ─► security::decrypt_in_place ─► nwk dispatch (command /
   data) ─► aps::Frame<'a> ─► aps dispatch (ack, dedupe, reassembly) ─►
   zdo | zcl | green-power | app indication (owned copies only where needed)
```

Inter-PAN frames (a stub NWK header of frame type 0b11, ZCL8 §13.3.4.5)
leave this path at the MAC: `panweave-runtime::touchlink` decodes the
`panweave-aps::interpan` headers and feeds the Touchlink Commissioning
command to the initiator or target machine of `panweave-bdb::touchlink`,
which drives the stack (channel switches, key transport, network start /
adoption / rejoin) through its `TouchlinkNode` view.

Transmit path builds frames outermost-last into a caller-provided buffer:
the APS payload is written first at the correct offset, then the APS header,
NWK header, security transform in place, then MAC header. No per-frame heap
allocation occurs.

## Memory model

All tables are `heapless` fixed-capacity containers sized by a `Capacities`
const-generic configuration or by role presets (`Capacities::COORDINATOR`,
`Capacities::ROUTER`, `Capacities::SLEEPY_END_DEVICE`). Table-full conditions
are reported as errors and follow the specification's replacement rules where
it defines any (e.g. route discovery table reuse, neighbor table eviction of
stale non-child entries). See `docs/memory.md` once benchmarks exist.

## Concurrency

* No global mutable state. Each stack instance owns its tables.
* Bounded queues everywhere; overflow policy is stated per queue
  (`docs/security-model.md` lists the drop policies).
* Security-critical events (key transport, leave, TC rejection) are never
  dropped silently; the runtime applies backpressure to the application
  side instead.
* The core is `Send` where the injected traits are `Send`; it does not
  require `Sync`.

## Timing

`panweave-types::time` defines `Instant` and `Duration` as monotonic
millisecond values. `panweave-runtime` maintains a timer wheel keyed by
protocol timer identifiers. Tests and simulation use `VirtualClock`
(`panweave-testkit`) to advance time deterministically.

## Security boundaries

See `docs/security-model.md`.

## Persistence

See `docs/storage-model.md`.

## Feature flags

| Feature | Effect |
|---|---|
| `alloc` | Enables `alloc`-backed convenience APIs (owned frames, `Vec` collections in host tooling). |
| `std` | Host-side: file storage, PCAP, CLI, `std::error::Error` impls. Implies `alloc`. |
| `serde` | `serde` derives on public value types. |
| `defmt` / `log` / `tracing` | Logging back-ends; at most one should be enabled by the application. |
| `crypto-software` | RustCrypto AES back-end (default for host and most MCUs). |
| `coordinator` / `router` / `end-device` | Role code paths; enabling a role never changes wire behaviour, only which state machines are compiled. |
| `green-power` / `direct` / `smart-energy` | Optional subsystems. `green-power` on `panweave-runtime` adds the Basic Proxy; `direct` on `panweave` makes `Node` a Zigbee Direct device (`panweave::direct`, the `Zdd` trait of the Commissioning Service) and adds `Event::Direct`. |
| `pcap` | PCAP export in the runtime and CLI. |

Invalid combinations (e.g. `end-device` without any role for a coordinator
build) are rejected with `compile_error!` in `panweave/src/lib.rs`.

## Code generation

DTL device-type definitions are generated from Panweave-maintained metadata
(`panweave-device-library/metadata/devices.toml`, produced once by
`scripts/dtl_metadata.py` from the specification text and maintained by
hand) by `cargo xtask codegen`. Generated files carry a header and are
checked in so that consumers do not need the generator; `cargo xtask codegen
--check` runs in the gate. ZCL clusters are hand-written in
`panweave-zcl/src/clusters/`; a metadata-driven generator for the full
library is planned.

## Cluster execution

The endpoint dispatcher (`panweave-zcl::layer`) executes the general
clusters whose semantics are fully specified — Identify, Groups, Scenes,
On/Off, Level Control, Color Control, Thermostat, Window Covering, Door
Lock, Poll Control, Alarms, Time, IAS Zone, IAS ACE, IAS WD, Commissioning and the Basic
Reset to Factory Defaults — and hands everything else to the application as
`ZclIndication::Command`. Attribute-only clusters (the measurement and
sensing clusters, Power Configuration) come with builders and application
setters (`temperature::set_measured`, `power_configuration::set_battery`)
that keep the range / alarm-state rules; alarm conditions are raised with
`Zcl::raise_alarm`, which logs them in the endpoint's Alarms server and
notifies the bound clients.
Executed clusters keep their state in the cluster instance (`ClusterState`,
the 100 ms `tick`) or the endpoint (the scene table), and inform the
application through `ZclEvent`s (`OnOff`, `Level`, `SceneRecalled`,
`FastPoll`, …) that the runtime re-exports as `StackEvent`s; the
application never re-implements a command's effect on the attributes. The
cross-cluster rules (Level Control ↔ On/Off, Table 3-55; the global scene of
§3.8.2.2.2; scene extension field sets) live in the dispatcher because only
it sees every cluster of an endpoint. Replies inherit the APS security of
the request. Reportable mandatory attributes are created with their BDB
§6.5 default reporting configuration.

## Conformance tracking

`conformance/*.toml` is the requirement inventory; `cargo xtask conformance`
renders `docs/conformance.md` and fails if a `tests = [...]` reference does not
resolve to an existing test function name in the workspace.

## Conventions

* Section references: `Spec: R23.2 §3.6.4.5.2`.
* Requirement IDs: `PW-<DOC>-<AREA>-<NNN>` (e.g. `PW-R23-NWK-017`).
* Tracked TODOs: `// TODO(PW-R23-SEC-042): ...`.
* No `unwrap`/`expect`/indexing on wire-derived data outside tests.
* Secret-bearing types redact `Debug`/`Display`.
