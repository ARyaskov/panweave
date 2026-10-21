# Hub diagnostics on the ESP32-C6

The hub firmware (`docs/esp32c6-hub.md`) carries a diagnostics layer for
bringing up boards and for finding out why a real device does not join,
does not finish its interview or reports the wrong state. Everything is
read over the same USB link and protocol as the rest of the hub, with the
same CLI.

> **Status.** Implemented, unit tested and tested in simulation; the
> firmware builds for the ESP32-C6. **None of it has run on a board yet**:
> values that come from the chip (reset reason, clock, flash size,
> partition table, radio driver counters, loop timing, USB byte counts,
> stack and heap measurements) have only been compiled, not observed. See
> [esp32c6-hardware-testing.md](esp32c6-hardware-testing.md).

## Contents

1. [Design rules](#design-rules)
2. [Architecture](#architecture)
3. [The trace](#the-trace)
4. [Record catalogue](#record-catalogue)
5. [Boot report](#boot-report)
6. [Counters and metrics](#counters-and-metrics)
7. [What is not measured](#what-is-not-measured)
8. [CLI](#cli)
9. [JSONL export schema](#jsonl-export-schema)
10. [Radio capture](#radio-capture)
11. [Security](#security)
12. [Resources](#resources)
13. [Target memory](#target-memory)
14. [Timing and the watchdog](#timing-and-the-watchdog)
15. [USB behaviour](#usb-behaviour)
16. [Partition validation](#partition-validation)

## Design rules

* **Binary only on USB.** The USB Serial/JTAG port carries Hub Protocol
  frames and nothing else; no text log is ever interleaved with them.
  Diagnostics are protocol messages the host asks for.
* **Polled, not pushed.** The trace is a ring buffer in the hub that the
  host reads in pages (`ReadTrace`). Diagnostics never take room in the
  event queue or the USB transmit queue that application events need.
* **Bounded and non-blocking.** Every buffer has a fixed capacity; when
  one is full the least important data is dropped and the drop is
  counted. Nothing waits for the host.
* **Nothing invented.** A value the platform cannot provide is absent
  (`unavailable` in the CLI, `null` in JSON), never zero or a guess.
* **No secrets.** No record or report has a field that can carry a key;
  captures keep frame headers only by default.

## Architecture

```text
 Panweave stack (runtime)                 panweave-hub engine            host
 ─────────────────────────                ───────────────────            ────
 MAC/NWK/APS counters ───────────────┐
 NWK pending-TX use, saturation ─────┤    Hub::poll_diagnostics
 join trace (12 milestones, drop     ├──► ┌─────────────────────┐
   oldest; Stack::next_join_record)  │    │ DiagLog<128>        │ ◄── ReadTrace (pages of 12)
                                     │    │ 32-octet records,   │ ◄── Set/GetTraceConfiguration
 hub: interview, IAS, ZCL, commands, │    │ filter before queue │ ◄── ClearTrace
   registry, persistence, session ───┘    └─────────────────────┘
                                          BootReport, counters ◄── GetBootReport / Get…Diagnostics
 firmware (ESP32-C6): reset reason,       CaptureBuffer<16>  ◄── Start/Stop/ReadCapture
   clock, partitions, driver counters,
   loop timing, USB bytes, radio frames ─► Hub::capture_frame (only while a capture runs)
```

* `panweave-runtime` keeps a small join trace (`join_trace.rs`): the
  milestones of every join the Trust Center handles (association,
  child joined, Update Device, the authorization decision, key transport
  sent / delivered / failed, TCLK requested / verified), separate from
  `StackEvent` so it costs nothing to applications that do not read it.
* `panweave-nwk` counts saturation and the high-water mark of its pending
  unicast table (`NwkStats::pending_full`, `pending_high_water`,
  `Nwk::pending_tx`).
* `panweave-storage` counts what a `NorFlashStore` did
  (`StoreStats`: formatted at open, damaged records skipped, writes,
  compactions, I/O errors).
* `panweave-hub` turns all of it into trace records and reports
  (`diag.rs`, `hub_diag.rs`, `protocol/diagnostics.rs`, `capture.rs`,
  `partitions.rs`, `esp32c6.rs`).
* The firmware fills in what only the chip knows (`src/bin/hub.rs`,
  `board.rs`, `radio.rs`, `runner.rs`).

## The trace

**Record.** Every record has a sequence number, a timestamp, a category,
a severity, a stable 16-bit code and up to seven optional fields:

| Field | Meaning |
|---|---|
| `seq` | 32-bit sequence number, wrapping; consecutive records differ by 1 |
| `at_ms` | milliseconds since boot, modulo 2³² (the page's 64-bit `uptime_ms` unwraps it) |
| `category` | `system`, `boot`, `usb`, `radio`, `mac`, `nwk`, `aps`, `trust-center`, `commissioning`, `zdo`, `zcl`, `interview`, `ias-zone`, `persistence`, `watchdog`, `resources` |
| `severity` | `trace` < `debug` < `info` < `warning` < `error` < `critical` |
| `code` | what happened (catalogue below); codes are never renumbered |
| `ieee`, `nwk` | the device concerned |
| `endpoint`, `cluster`, `tsn` | the Zigbee transaction (the TSN correlates with a capture) |
| `status` | a Zigbee status or a small code-specific value |
| `arg` | a 32-bit code-specific value |

Records are stored packed in 32 octets.

**Filtering before queueing.** The trace configuration (minimum severity
and a category mask, default `info` and every category) is applied before
a record is built into the ring: a filtered record costs nothing and is
only counted (`filtered`). `critical` records bypass the filter.

**Overflow.** The ring holds 128 records. When it is full, a new record
replaces the oldest record of the same or lower severity; when every
stored record is more severe, the new record is dropped. Either way
`dropped` grows. A reader that asks for records older than
`first_available` learns how many it missed; the CLI prints the gap.

**Reading.** `ReadTrace { from, max ≤ 12, ieee }` returns the records with
a sequence number at or after `from` (optionally only one device's),
`next` to continue from, `first_available`, `dropped` and `uptime_ms`. A
whole-device read scans the ring once per page.

**Configuration.** `SetTraceConfiguration { min_severity, categories }`
(Admin) takes effect for the next record and is itself recorded
(`trace-configured`). `ClearTrace` (Admin) empties the ring and records
how many records it removed.

## Record catalogue

The authoritative list with field use per code is `panweave_hub::diag::code`.
Groups:

| Codes | Category | Records |
|---|---|---|
| 0x00xx | system | trace cleared / configured, capture started / stopped (`status` 1 = time limit) |
| 0x01xx | boot | boot completed, network restored / formed / restore failed / not formed (corrupt store), registry restored (count) / RAM only, partition problem (finding), formation failed, network record unusable (reason), network restore retry |
| 0x02xx | usb | host output discarded (host stopped reading), corrupt frame, oversize frame, request rejected (version / malformed), unauthorized (`arg` = request id), response dropped |
| 0x03xx | radio / watchdog | transmit fault, configuration error; `stall-suspected` (Error: evidence of a stall, the radio was re-armed; `status` = cause 1 radio driver, 2 stack progress; `arg` = radio idle ms), `stall-confirmed` (Critical: the recovery did not help; `arg` 1 = the watchdog will reset the chip, 0 = not escalated because this boot followed a watchdog reset), `previous-stall-reset` (Critical, at boot: the previous run ended in a supervisor reset; `status` = cause) |
| 0x0501 | nwk | pending-unicast table full |
| 0x07xx | trust-center | association request (capability), child joined (join type), Update Device, decision (`status`: 0 negotiate key, 1 transport network key, 2 allow, 3 ignore, 4 remove), key sent, key delivered, key delivery failed (APS status), TCLK requested (granted or not), TCLK verified, key exchange pending, key exchange timed out (device removed), authorized (`status` 1: through an exemption), join trace lost; `arg` = milliseconds since the device's previous milestone |
| 0x08xx | commissioning | permit join opened / closed, joins refused again after the window, device authorized / announced / rejoined / left, registry full, address changed, device discovered, device not authorized (announce or traffic ignored; `status`: authorization), key-exchange exemption granted / revoked / expired / used, exemption withdrawn (a new unsecured join with an admitted device's address: it must complete the key exchange) |
| 0x0901 | zdo | ZDP request timed out |
| 0x0Axx | zcl | default response error, attribute error, reporting refused, command sent / responded / confirmed / timed out / failed / retried, unsupported command |
| 0x0Bxx | interview | started, request, answer, timeout, step skipped, stalled, resumed, completed (`status` 1 = partial), send deferred; `arg` = stage << 8 \| step, `status` = attempt |
| 0x0Cxx | ias-zone | zone attributes read, CIE address written, enroll request / response / unsolicited / confirmed, not enrolled, zone status, re-enrolment |
| 0x0Dxx | persistence | store failed (`status`: 0 full, 1 I/O, 2 buffer), record skipped (IEEE), index corrupt, record written |
| 0x0E01 | watchdog | watchdog armed (`arg` = seconds) |
| 0x0Fxx | resources | loop overrun (`arg` = µs), hub events dropped (at the start of a loss streak), stack events dropped |

**IAS zone status records** keep the raw and the interpreted value
together: `arg` = raw ZoneStatus (low 16 bits) plus flags —
contact known / open, leak known / leak, test mode (alarms not
interpreted), manufacturer override applied, zone type unknown (alarms
not interpreted) (`panweave_hub::diag::ias_bits`). So a wrong "dry" can
be traced to the exact bits the device sent and the rule applied to them.

## Boot report

`GetBootReport` (CLI `diagnostics system`):

| Field | Source on the ESP32-C6 | When unavailable |
|---|---|---|
| chip, revision | `ESP32-C6`, eFuse chip revision | — |
| firmware, build | crate version, `PANWEAVE_BUILD_ID` (git revision, `-dirty`) | build `unknown` without git |
| reset reason | `rtc_cntl::reset_reason` (raw code kept) → `cold-boot`, `software-reset`, `watchdog-reset`, `other-reset`, `unknown` | absent |
| CPU clock | `clock::cpu_clock()` | absent |
| flash size | the flash driver's capacity (`esp-storage` `FlashStorage::capacity`) | absent |
| partitions | the table read from flash (8 entries max), findings | `partition_table_read` false |
| registry area | the `hubdata` partition used | absent: RAM-only registry |
| IEEE, channel | the stack | — |
| network | the boot policy's outcome (`restored`, `formed`, `read-failed`, `corrupt-not-formed`) | — |
| registry | devices restored, persistent or not | — |
| USB, watchdog | link taken over, watchdog timeout | — |
| boot time | reset to main loop | absent |

The raw reset reason distinguishes, for example, a USB Serial/JTAG reset
(code 0x16, what `self-test --allow-reboot` and flashing tools cause)
from a power-on (0x01) or a watchdog (0x07–0x09, 0x0b, 0x0d, 0x10–0x12).
A watchdog reset fails the smoke test.

## Counters and metrics

| Report | Contents |
|---|---|
| `GetRadioDiagnostics` | channel, TX power; driver adapter: transmissions started / acknowledged / without ACK-or-CCA / CCA failures of frames without ACK request / faults, frames received / malformed, configuration errors / flushes, last RSSI and LQI; MAC service: unicast TX, software retries, failures, RX, broadcast TX / RX, queue full; NWK: malformed, security failures, replays, no route, pending unicasts (now, held for sleepy children, capacity 4, high water, refused when full); APS: acknowledged, retries, unacknowledged, security drops, malformed |
| `GetStorageDiagnostics` | network outcome at boot; registry persistent, devices, writes, errors (and full errors), records skipped at boot, last error; both stores' capacity, free space, writes, compactions, damaged records, I/O errors, formatted at open |
| `GetRuntimeDiagnostics` | uptime; loop iterations, longest loop turn, overruns (> 50 ms), longest radio step; watchdog; length / capacity / high-water mark of hub events, awaited Zigbee transactions, host commands, trace, USB transmit queue (octets), capture buffer; drops of hub events, stack events, trace records, join milestones, captured frames; USB octets in / out, output discards; devices, interviews active / stalled; target measurements: main stack size and watermark, heap size / in use / peak, loop turns over 20 ms, longest hub poll, time since the last completed transmission, radio steps cut by a receive burst |
| `GetSecurityStatus` | the Trust Center policy (key exchange required, window), devices pending, removed for not completing the exchange, application frames dropped from unauthorized devices, link-key table use, exemptions, registered devices without access |
| `GetDiagnostics` (0.2.0) | unchanged |

**PENDING_TX.** The NWK layer keeps four unicasts in flight, frames for
sleepy children included. The radio report shows how close the hub runs
to that limit; the limit itself was deliberately not changed — the
numbers from a real installation should decide it.

## What is not measured

| Metric | Why |
|---|---|
| Energy detection, channel noise | `esp-radio` 1.0.0-beta.1 has no energy-detect API for 802.15.4 |
| Driver receive-queue overflow | the driver counts it internally and only logs it; not readable by the application |
| ACK missing vs CCA failure | the driver reports the same outcome for both |
| Per-device RSSI | only the last received frame's RSSI is known; LQI per device only for direct neighbours |
| Exact stack use | the watermark is a lower bound (see [Target memory](#target-memory)); per-function frame sizes need nightly `-Z emit-stack-sizes`, not used |
| Interrupt stack use separately | interrupts run on the main stack; their use is inside the watermark, not separable |
| CPU time per subsystem | only the loop turn, the radio step and the hub poll are timed |
| Coexistence (Wi-Fi / BLE) | not supported with 802.15.4 by the driver (`docs/esp32c6-hub.md`) |

In simulation the platform fields (driver, loop timing, reset reason,
clock, USB counters, every target measurement) are absent by design: the
engine never fabricates them, and host `size_of` figures are never
reported as target measurements.

## CLI

```text
panweave-hub-cli diagnostics system
panweave-hub-cli diagnostics radio
panweave-hub-cli diagnostics storage
panweave-hub-cli diagnostics runtime
panweave-hub-cli diagnostics trace
panweave-hub-cli diagnostics watch --level warning --category interview,ias-zone
panweave-hub-cli diagnostics device 00124b002a3b4c5d
panweave-hub-cli diagnostics interview 00124b002a3b4c5d
panweave-hub-cli diagnostics export --output trace.jsonl [--ieee 00124b002a3b4c5d]
panweave-hub-cli diagnostics configure --level debug --category all
panweave-hub-cli diagnostics clear
panweave-hub-cli capture export --output air.pcap --seconds 120 --metadata air.jsonl
panweave-hub-cli security
panweave-hub-cli device 00124b002a3b4c5d fingerprint --json
panweave-hub-cli self-test
panweave-hub-cli partitions check partitions-hub.csv --image hub.bin
```

* `--json` (global) prints the reports, the trace, the security status,
  a device fingerprint and the smoke test as JSON (one object per line
  for records).
* `watch` follows the trace from the newest record, every 300 ms, until
  Ctrl+C; `--level` and `--category` filter on the host. If the hub keeps
  less than asked (its own configuration), the CLI says so.
* `interview <ieee>` prints the device's interview, ZDO, ZCL, IAS and
  Trust Center records with a summary: requests vs answers, timeouts,
  skipped steps, stalls, the last stage, and a plain-language hint (never
  answered → sleepy, out of range or not on this network; enrolment not
  confirmed → no notifications).
* Ctrl+C stops `watch`, `capture export`, `self-test` and `hil` cleanly
  (the capture is stopped on the hub, the pcap file finished); a second
  Ctrl+C exits at once.
* Exit codes: 0 success, 1 failure (including a FAIL in a test), 2 usage,
  3 hub unreachable (no port, port busy, no answer).
* Against a 0.2.0 firmware every diagnostic command reports that the
  firmware does not support it; the other commands work.

## JSONL export schema

`diagnostics export`, `diagnostics trace --json` and `watch --json` write
one JSON object per record:

| Key | Type | Meaning |
|---|---|---|
| `seq` | integer | sequence number |
| `uptime_ms` | integer | milliseconds since boot (unwrapped) |
| `severity` | string | severity name |
| `category` | string | category name |
| `code` | integer | record code |
| `code_name` | string | its name (`interview-timeout`, …) |
| `ieee` | string or null | `00:11:22:33:44:55:66:77` |
| `nwk`, `endpoint`, `cluster`, `tsn`, `status`, `arg` | integer or null | as recorded |
| `detail` | string | the CLI's decoding of `status` / `arg` |

A line `{"gap": "...", "count": N}` marks records lost before the export
or during `watch`. Field names are stable; new keys may be added.

`capture export --metadata` writes one object per frame: `seq`,
`uptime_ms`, `direction` (`rx` / `tx`), `channel`, `captured_length`,
`original_length`, `rssi_dbm`, `lqi`, `acked`, `no_ack`, `tx_fault`,
`redacted` (payload omitted), `summary` (MAC / NWK header summary of the
captured bytes).

## Radio capture

With the `capture` feature (default; `panweave-hub/radio-capture`) the
firmware offers every frame the radio sends and receives to a 16-frame
buffer, which copies a sanitized prefix **only while a capture runs**.
Without the feature the engine holds no buffer and the capture requests
answer `NotSupported` (the same host CLI works with both builds).

**Where frames are taken.** At the radio boundary, in the firmware's
radio step (`Runner::step_observed`): received frames as the driver
delivered them, transmitted frames as handed to the driver — after NWK
and APS encryption, exactly the bytes on the air (without FCS). The
capture never sees decrypted payloads, key tables or stack buffers.

**Modes** (`StartCapture { seconds, mode }`, Admin, 1–3600 s):

| Mode | Kept of each frame |
|---|---|
| `metadata` | the MAC header (frame type, sequence number, addresses) |
| `sanitized` (default) | MAC beacons, acknowledgements and MAC commands whole; for data frames the MAC header and the NWK header including its auxiliary security header (frame counter, key sequence, source), plus the command identifier of an unsecured NWK command — never the NWK payload |
| `raw` | the whole frame — CLI `--mode raw --allow-raw`; a warning is printed and the start is a Warning trace record |

**Sensitive frame categories** — why the rule is "headers only", not
"NWK-unsecured only":

| Frame | Key material | Visible to whom |
|---|---|---|
| Transport Key (network key) to a joiner, NWK unsecured | the network key, APS-encrypted with a key-transport key derived from the joiner's link key | anyone, when that link key is the well-known one |
| Transport Key (TC link key), NWK secured | a unique link key, APS-encrypted with a key derived from the current link key | anyone holding the network key, when the current key is the well-known one |
| Tunnel / Relay Message to a router or joiner | either of the above, nested | as above |
| Network key update / Switch Key | the new key (broadcast: NWK security only) | anyone holding the current network key |
| Request / Verify / Confirm Key, key negotiation (DLK) | key hashes, public values | — (no key, but nothing gained by keeping them) |
| Green Power commissioning | a GPD key, possibly unprotected | anyone |
| Frames the parser does not recognize, malformed or truncated headers, MAC-secured or 802.15.4-2015 frames | unknown | — kept to the MAC header at most, or nothing |

**PCAP.** `capture export` writes link type 230
(`LINKTYPE_IEEE802_15_4_NOFCS`). A cut frame is a record whose captured
length is shorter than its original length (`PcapWriter::write_truncated`),
so Wireshark marks it as cut instead of misparsing a shorter frame;
nothing is ever filled in or fabricated. Sanitized files decode MAC and
NWK headers; payload decryption needs `raw`.

* The buffer is drained with `ReadCapture` (3 frames per page); a frame
  that arrives while it is full is dropped and counted — the export
  reports how many, so an incomplete capture is never taken for a
  complete one. Offering a frame while no capture runs costs one
  comparison; a full buffer costs a counter increment: capture never
  makes the radio wait.
* A capture ends by itself at its deadline (`capture-stopped`, status 1)
  — also when the host vanished — or on `StopCapture`; frames are kept in
  RAM only, never written to flash, and replaced by the next capture.
* Timestamps are the hub's uptime, in microsecond pcap fields with
  millisecond resolution.
* The hub serves USB after the radio, at most 256 octets of input per
  loop turn; a busy network can overrun the 16-frame buffer. Use a
  dedicated sniffer for long or complete captures.

## Security

* Changing the trace configuration, clearing the trace, capture and
  key-exchange exemptions require `Access::Admin`; reading reports, the
  trace and the security status requires `Access::Monitor`. Refusals are
  recorded (`usb-unauthorized` with the request id). The USB session is
  Admin: whoever is physically connected (or any program on the
  connected computer) has full access — treat that computer as part of
  the hub. A future wireless transport must start at Monitor.
* No record, report or JSON field can carry a key: records hold
  identifiers, codes and counters; the boot report holds identifiers
  (IEEE, PAN), never key material. `Key128`'s `Debug` prints
  `[REDACTED]`, so even debug formatting of stack structures shows no
  key. CLI output is built from these messages only.
* `security` shows the frames refused by the Trust Center's
  application-frame authorization by reason (`unresolved`,
  `inconsistent`, `unknown`, `pending`, `incomplete`) and how many
  commissioning grants were used by a join or expired unused
  ([esp32c6-hub.md](esp32c6-hub.md#security)). The counters hold no
  addresses; the trace records which device was refused.
* Captures are off by default, Admin only, time-limited, sanitized by
  default ([Radio capture](#radio-capture)), and a raw capture needs an
  explicit acknowledgement on the CLI.
* Tests plant synthetic secrets in frames of every category above and
  check that the sanitized and metadata modes, the PCAP file and the JSONL
  metadata never contain them (`panweave-hub/tests/hub_capture.rs`,
  `panweave-hub-cli` unit tests).
* A panic prints a message on the USB port before the chip resets
  (`esp-backtrace`): the only text that can appear on it. Panic messages
  do not format keys.

## Resources

| Item | Size (host `size_of`; not a target measurement) |
|---|---|
| Trace ring | 128 × 32 octets + state = 4 128 octets |
| Capture buffer | 2 488 octets with `capture`; none without |
| Hub engine (everything above included) | 28 736 octets with capture, 26 248 without |
| Join trace in the runtime | 12 milestones (≈ 300 octets) |
| Trust Center authorization state | ≈ 600 octets (8 pending, 8 exemptions, 32 swap-out renewals) |
| Link-key table | 32 entries × 88 octets (was 8) |

Recording a record is a filter check and a 32-octet copy; no record is
formatted on the chip.

## Target memory

`diagnostics runtime` reports what the ESP32-C6 measures about itself
(`TargetMetrics`), each value absent when not measured:

* **Main stack**: size from the linker symbols (`_stack_start`,
  `_stack_end`), and a high-water mark. At start-up the firmware paints
  the free stack — from the word after esp-hal's stack guard up to 1 KiB
  below the current stack pointer, with interrupts off — and every 10 s
  scans from the bottom for the first overwritten word
  (`examples/esp32c6-super-mini/src/memory.rs` documents the layout and
  the safety argument). The figure is a **lower bound**: a frame that
  reserved stack without writing it is not seen, and use before painting
  counts only through `main`'s own frame. Interrupt handlers share the
  stack, so their use is included.
* **Heap**: size, in use and peak from `esp-alloc` (`internal-heap-stats`);
  the heap is `esp-radio`'s (32 KiB); the hub itself does not allocate.
* Static RAM is what `scripts/elf_size.py` reports; the hub engine, the
  session and the stack are locals of `main` and appear only in the
  stack figures.
* **Health**: `health` (the supervisor's state) and `radio_recoveries`
  (how often the radio was re-armed), see
  [Timing and the watchdog](#timing-and-the-watchdog).

## Timing and the watchdog

* **Loop**: longest turn, turns over 50 ms (`loop-overrun` records),
  turns over 20 ms (`loop_over_20ms`), longest radio step, longest hub
  poll (registry flash writes happen there). 20 ms matters: after a
  sleepy child's data request is acknowledged (the driver always sets
  frame pending), the child listens for about `macMaxFrameTotalWaitTime`
  (~20 ms at 2.4 GHz); a longer turn can make it miss its frame, which it
  then gets at its next poll. MAC acknowledgements themselves are sent
  by the radio hardware and do not depend on the loop.
* **Critical sections**: flash erase and write stall the CPU (the flash
  cache is off) for the duration of the operation; compaction of a store
  half erases sectors and is the longest. They happen in the stack's
  poll (radio step) and the hub's poll, so they show in those timings.
  Painting the stack disables interrupts once, at start-up.
* **Receive bursts**: a radio step handles at most 32 received frames,
  then the rest of the loop (USB, watchdog) runs; the next turn starts at
  once (`rx_bursts_cut`).
* **Diagnostics overhead**: a record is a filter check and a copy; an
  offered frame while no capture runs is one comparison; reports are
  built only when asked. A deterministic simulation test checks that the
  most verbose trace plus a capture of every frame do not change a
  join-and-interview by one millisecond
  (`full_diagnostics_do_not_change_protocol_timing`); CPU cost on the
  target shows in the loop metrics.
* **Watchdog**: 10 s, fed every loop turn unless the health supervisor
  (`panweave_hub::supervisor::HealthSupervisor`) has evidence of a stall.
  Its inputs each turn: transmissions completed, unacknowledged
  (no ACK, CCA failure) and faulted by the driver, frames received,
  queue-full events (MAC queue, NWK pending table) and whether the
  stack's deadline is overdue. Silence is **not** evidence: an empty
  network, a network of sleepy sensors that report once an hour, a
  vanished host, flash writes — all stay healthy (simulated for an hour
  in `panweave-hub/tests/hub_watchdog.rs`).

  | Health (`health`) | Condition |
  |---|---|
  | `healthy-idle` | no traffic in the last 60 s |
  | `healthy-active` | frames completed or received in the last 60 s |
  | `degraded` | unacknowledged frames or full queues, but frames still complete |
  | `suspected-stall` | stack deadline overdue 10 s, or 5 driver faults / transmissions that never complete within 30 s with frames waiting |
  | `confirmed-stall` | still stalled 60 s after a recovery |

  Actions: a suspected stall logs `stall-suspected`, re-applies the radio
  configuration and restarts reception (`radio_recoveries`) and keeps
  feeding; a confirmed stall logs `stall-confirmed`, stores the cause in
  the hub's storage and stops feeding, so the chip resets and resumes
  from flash; the next boot logs `previous-stall-reset` once and erases
  the record. After a watchdog reset the supervisor never escalates
  again (`stall-confirmed` with `arg` 0), so a fault that survives a
  reset cannot make a reset loop. `radio_idle_ms` is the time since the
  last completed transmission or reception (`radio_tx_idle_ms` in an
  unreleased 0.2.1 build).

## USB behaviour

* The session never writes anything but protocol frames.
* A host that stops reading: after 2 s without progress the hub discards
  its queued output (`usb-output-discarded`, counted in
  `usb_discards`); a host that comes back resynchronizes at the next
  frame delimiter.
* Corrupt and oversize frames are dropped (`usb-frame-corrupt`,
  `usb-frame-oversize`) and the stream resynchronizes; the smoke test
  checks this on hardware.
* The CLI keeps DTR and RTS released (they reset the chip in the USB
  Serial/JTAG's flashing pattern) and uses RTS deliberately only for
  `self-test --allow-reboot`, then waits for the port to re-enumerate and
  reconnects.

## Partition validation

The same rules (`panweave_hub::partitions::validate`) run in three
places: the firmware's `build.rs` on `partitions-hub.csv`, the CLI's
`partitions check` on any CSV (optionally with the image file to check
that it fits its partition), and the firmware at boot on the table read
from flash (read only; findings go to the boot report and the trace).

| Finding | Fatal |
|---|---|
| partitions overlap; a partition overlaps the table (0x8000–0x8FFF) or leaves the flash | yes |
| a data partition not 4 KiB aligned, an app partition not 64 KiB aligned | yes |
| duplicate label, no app partition, image larger than its partition | yes |
| `nvs` not at 0x9000 / 24 KiB (the stack's region; moving it orphans the network) | yes |
| `hubdata` not a data partition, or under 8 KiB | yes |
| no `hubdata` | no: the registry is RAM only |

The layout itself is unchanged from 0.2.0.
