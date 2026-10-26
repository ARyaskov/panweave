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
| `Aib` | Trust Center address and the index of `LinkKey` partners (up to `LINK_KEYS` = 32, 8 with `small-tables`) | with `LinkKey` | no |
| `Bindings` | binding table (§2.2.8.1) | `ApsAction::Persist(Bindings)`, ZDO Bind / Unbind / Clear_All_Bindings | no |
| `Groups` | group table | `ApsAction::Persist(Groups)` | no |
| `GreenPower` | one Proxy Table entry per `id` (index 0–19) in the OTA format of GP Basic §A.3.4.2.2.1; one Sink Table entry per `id` 0x100 + index in the format of §A.3.3.2.2.1 | `ProxyEvent::TableChanged` / `SinkEvent::TableChanged` (pairings, forwarded and accepted frames update the counter) | counter: monotonic per GPD, never rolled back |
| `DirectPastKeys` | the network keys a ZDD switched away from, with their sequence numbers (ZD 1.1 §9.1) | every `StackEvent::NetworkKeySwitched` | yes |
| `DirectConfig` | Zigbee Direct interface state and Anonymous Join Timeout (ZD 1.1 §11.3.5.4, persistent by requirement) | every Configure Zigbee Direct Interface / Anonymous Join Timeout | yes |
| `DirectAdminKey` | the Admin key a ZVD handed the ZDD with the network parameters (ZD 1.1 §6.3.2.1; changed only by a factory reset) | Form / Join Network with an Admin Key TLV | yes |
| `StartupSets` (per endpoint) | the saved startup attribute sets of a Commissioning server (ZCL8 §13.2.2.3.2) | Save / Restore / Reset Startup Parameters | yes |
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
   `Stack::restore_detail()` says why, because "no usable network" is not
   always "factory new":

   | `RestoreDetail` | Storage |
   |---|---|
   | `Empty` | neither `Nib` nor `NetworkKeys`: factory new |
   | `Incomplete` | only one of them (an interrupted formation, factory reset or write) |
   | `UnknownFormat` | a record in a format this firmware does not know (a newer firmware's) |
   | `Malformed` | a record that does not decode, or keys without an active one |

   A storage error is returned as `Err` (nothing restored,
   `RestoreDetail::NotRun`); calling `restore` again later is safe.
   `restore` never writes, so whatever is stored stays for a later
   firmware or an operator. Only `Empty` should lead an application to
   form a network: the hub's policy is `NetworkRestore::decide`
   (`docs/esp32c6-hub.md`), tested with every state above in
   `panweave-runtime/tests/restore_detail.rs`.

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

## Trust Center authorization state

Whether a device completed the key exchange the Trust Center requires
(`panweave_runtime::authorization`) is not stored separately: it is
derived from the device's `LinkKey` record (a unique key with the
verified attribute). The key-exchange window of a pending device lives in
RAM only, so a restart can never turn a pending device into an authorized
one; it simply has no access until it rejoins and completes the
exchange. Exemptions from the requirement are the application's to
store (the hub keeps them in its registry records as an optional trailing
flag octet, written only when set, so records without it are unchanged).
Only *admitted* exemptions (a device that joined under one) are
persisted; an unused commissioning grant lives in RAM and ends at a
restart, so a reboot never reopens a grant window. The held-frame queue
and the address-resolution requests of application-frame authorization
are RAM only as well.

## Supervisor reset record

When the hub's health supervisor lets the watchdog reset the chip after
a confirmed stall, it first stores one small record in the hub's own
store: `Kind::Application`, id `0xFFFF_FFFF_FFFF_FFFE`, six octets —
format version 1, the stall cause (1 radio driver, 2 stack progress) and
the uptime in seconds (little endian). The next boot reads it, logs
`previous-stall-reset` and erases it, so it is reported exactly once.
It is written only on that path (never during normal operation), holds
no key or address, and a store that cannot take it simply loses the
report, not the reset.

## Experimental notification records

With the hub's `alerts` feature and the mode enabled
([esp32c6-wifi-alerts.md](esp32c6-wifi-alerts.md)), the hub store also
holds `Kind::Application` records with ids whose top octet is 0xFF (an
EUI-64 with the group bit set, so never a device's IEEE address):

| Id | Record |
|---|---|
| `0xFFFF_FFFF_FFFF_FF10` | settings: enabled, notified kinds, delay, budget, SSID, Wi-Fi password and bot token (**plain text**: no flash encryption), chat id |
| `0xFFFF_FFFF_FFFF_FF11` | meta: boot counter, overflow count and the first and last lost event ids |
| `0xFFFF_FFFF_FFFF_FF12` | the last delivery acknowledgement: Telegram `message_id`, the event ids it covered |
| `0xFFFF_FFFF_FFFF_FF20` + slot (16 slots) | one pending event: id, kind, sensor, raw zone status, boot and monotonic time, attempt count, possible-repeat marker |

The acknowledgement is written before the delivered slots are erased; a
boot completes an interrupted erase. While the mode is disabled none of
these records is read or written.
