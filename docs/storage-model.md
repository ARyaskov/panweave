# Storage model

Panweave separates *what* must survive a reset (R23.2 section 3.6.9, BDB 3.1
section 6.7, GP A.3.6, ZD 1.1 section 7.3) from *how* a backend stores it.

## Records

`panweave-storage` defines a small set of typed records, each with a
version tag and a stable binary encoding (`panweave-codec`):

| Record | Contents (paraphrased) | Secret |
|---|---|---|
| `NetworkIdentity` | extended PAN ID, PAN ID, channel page/number, short address, device type, update ID, TC address, network manager address, stack profile | no |
| `NetworkKeys` | active key sequence number, up to two network keys with sequence numbers | yes |
| `FrameCounters` | outgoing NWK frame-counter reservation, APS counter reservation | no (but integrity-critical) |
| `LinkKeys` | link key table entries (partner, key, type, attributes, incoming/outgoing counters) | yes |
| `TrustCenterState` | policy, passphrase (hashed), authorised device list, interview state | yes |
| `Neighbors` | parent and child entries needed to resume operation without rejoin | no |
| `AddressMap` | short/extended address pairs | no |
| `Bindings` / `Groups` | APS binding and group tables | no |
| `Commissioning` | BDB commissioning attributes (`bdbNodeIsOnANetwork`, join mode, TCLK exchange state) | no |
| `GreenPower` | proxy/sink tables (feature `green-power`) | partially (GPD keys) |
| `Direct` | ZDD provisioning state (feature `direct`) | yes |
| `Application` | opaque application record | app-defined |

## Backend trait

```rust
pub trait Storage {
    type Error;
    async fn load(&mut self, kind: RecordKind, into: &mut [u8]) -> Result<Option<usize>, Self::Error>;
    async fn commit(&mut self, kind: RecordKind, bytes: &[u8]) -> Result<(), Self::Error>;
    async fn erase(&mut self, kind: RecordKind) -> Result<(), Self::Error>;
}
```

`commit` MUST be atomic: after a power loss, `load` returns either the
previous or the new record, never a mixture. Backends targeting raw flash
implement this with two-slot journaling plus a CRC-32 trailer (reference
implementation in `panweave-storage::flash`). Host backends use
write-to-temp + rename.

## Frame-counter reservation

Writing flash on every transmitted frame is unacceptable for wear and
latency. Panweave reserves counters in windows:

```
persisted: reserved_until = N
boot:      next_counter    = N          (never lower)
tx:        if next_counter + margin >= reserved_until {
               commit(reserved_until = next_counter + window)   // atomic
           }
           use next_counter; next_counter += 1
```

Defaults: `window = 1024`, `margin = 64`. The commit is issued asynchronously
ahead of need so it does not stall transmission; if it has not completed by
the time `reserved_until` is reached, transmission stalls (safe) instead of
reusing a counter (unsafe). A key switch resets the counter to zero per
R23.2 section 4.3.4 and commits a fresh reservation before the first
frame under the new key.

## Wear management

* Only changed records are rewritten; the runtime tracks a dirty set.
* Records are written in the order of importance if a batch is interrupted:
  frame counters, keys, identity, tables.
* Backends may coalesce commits within a short window as long as atomicity
  and ordering are preserved.

## Backends provided

* `MemoryStorage` (testkit and simulation, with fault injection).
* `FileStorage` (`std`), single-directory, one file per record, atomic
  rename.
* `FlashJournal<F: NorFlash>` reference implementation for embedded targets
  (behind the `embedded-storage` feature).
