# Storage model

Panweave separates *what* must survive a reset (R23.2 §3.6.9, §2.2.8.1,
§4.4.12.1, §3.6.10.7; BDB 3.1 §6.7) from *how* a backend stores it. The
core never touches a file system or flash driver: it writes small,
versioned records through the `panweave_storage::Storage` trait and the
runtime (`panweave-runtime::persist`) decides when.

## Records

Records are addressed by `Key { kind, id }`. `id` is 0 for singletons and
the partner IEEE address for per-device records. Every record starts with
a format octet so that a later layout can migrate or reject old data.

| `Kind` | Contents (paraphrased) | Trigger | Secret |
|---|---|---|---|
| `Nib` | PAN ID, extended PAN ID, network address, channel page / channel, `nwkUpdateId`, depth, parent address and IEEE, network manager, device type, router-started flag, distributed flag, parent information, stack profile | every `NwkAction::Persist` | no |
| `Children` | end-device children: IEEE, network address, End Device Configuration, Device Timeout, rx-on flag (§3.6.9, §3.6.10.7) | every `NwkAction::Persist` | no |
| `NetworkKeys` | active sequence number, every network key slot | every `NwkAction::Persist` | yes |
| `NwkFrameCounter` | outgoing NWK frame-counter reservation bound | before the reservation is used | integrity-critical |
| `LinkKey` (per partner) | key, kind (global / unique), attributes, incoming counter, outgoing reservation bound, frame-counter-sync flag | `ApsAction::Persist(LinkKeys)` | yes |
| `ApsFrameCounter` (per partner) | outgoing APS frame-counter reservation bound | before the reservation is used | integrity-critical |
| `Aib` | Trust Center address and the index of `LinkKey` partners | with `LinkKey` | no |
| `Bindings` | binding table (§2.2.8.1) | `ApsAction::Persist(Bindings)`, ZDO Bind / Unbind / Clear_All_Bindings | no |
| `Groups` | group table | `ApsAction::Persist(Groups)` | no |
| `GreenPower` | one Proxy Table entry per `id` (index) in the OTA format of GP Basic §A.3.4.2.2.1 | `ProxyEvent::TableChanged` (GP Pairing, forwarded frames update the counter) | counter: monotonic per GPD, never rolled back |
| `Application` | opaque application record | application | app-defined |

Per R23.2 §4.4.12.1 the `Timeout` and `VerifiedFrameCounter` of a key pair
entry are not persisted. The incoming counter is stored so that a rebooted
Trust Center keeps rejecting replays from before its reset.

Records are written with `panweave_codec::Writer`, never `Debug`
formatting, and keys are never logged: the backend is expected to be the
device's protected non-volatile memory.

## Backend trait

```rust
pub trait Storage {
    fn store(&mut self, key: Key, data: &[u8]) -> Result<(), StorageError>;
    fn load(&mut self, key: Key, buf: &mut [u8]) -> Result<Option<usize>, StorageError>;
    fn erase(&mut self, key: Key) -> Result<(), StorageError>;
    fn erase_kind(&mut self, kind: Kind) -> Result<(), StorageError>;
}
```

`store` returns only after the data is durable and MUST be atomic: after a
power loss, `load` returns either the previous or the new record, never a
mixture. Backends targeting raw flash should implement this with two-slot
journaling plus a CRC trailer; host backends use write-to-temp + rename.
The trait is synchronous because the stack is sans-I/O; an asynchronous
backend wraps it by completing the write before returning from `poll`.

There is deliberately no enumeration primitive (it is expensive on
journaled flash). Per-partner records are indexed from the `Aib` record.

## Frame-counter reservation

Writing flash on every transmitted frame is unacceptable for wear and
latency. Panweave reserves counters in windows
(`panweave_security::frame_counter::OutgoingCounter`):

```
persisted: reserved_until = N
boot:      next_counter    = N          (never lower)
tx:        if next_counter + margin >= reserved_until {
               store(reserved_until = next_counter + window)   // atomic
           }
           use next_counter; next_counter += 1
```

Defaults: `window = 1024`, `margin = 64`. The reservation is surfaced as
`NwkAction::CounterReservation` / `ApsAction::CounterReservation`; the
layer keeps transmitting from the current window while the runtime stores
the new bound and stalls (safe) instead of reusing a counter (unsafe) when
the store has not completed by the time the window is exhausted. A key
switch resets the counter only when it is above `0x8000_0000`
(R23.2 §4.3.4) and commits a fresh reservation before the first frame
under the new key.

## Warm start

`Stack::restore()` runs the BDB 3.1 §7.1 "restore persistent data" step:

1. `Nib` and `NetworkKeys` present → identity and keys are restored, the
   outgoing NWK counter resumes at the persisted bound, `Aib`, `LinkKey`,
   `Children`, `Bindings` and `Groups` follow, the NWK layer is warm
   started (§3.6.1.12) and children get a full timeout period
   (§3.6.10.8). Returns `Restored::OnNetwork`.
2. Otherwise nothing is touched and `Restored::FactoryNew` is returned.

`Stack::resume()` then continues per BDB 3.1 §10.1: the coordinator and
routers restart routing and re-announce; end devices perform a secured
rejoin. `Stack::erase_persisted()` is the factory-reset counterpart.

Sequence numbers (`nwkSequenceNumber`, the APS counter) are seeded from
the RNG on every boot so that the first frames after a reset do not
collide with entries still live in peers' duplicate rejection tables
(see ADR-0006).

## Wear management

* Only the records whose layer flagged a change are rewritten.
* Records are written in order of importance: frame counters, keys,
  identity, tables.
* Backends may coalesce stores within a short window as long as
  atomicity and ordering are preserved; the runtime issues stores from
  `poll`, never from interrupt context.

## Backends provided

* `MemoryStorage<N, S>` (tests, simulation and RAM-only deployments).
* File and flash-journal backends are planned (`TODO(PW-STO-004)`).
