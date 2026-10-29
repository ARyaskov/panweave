# Panweave Lite

Panweave Lite is the Panweave Zigbee stack dimensioned for a battery IAS
Zone sensor (door / window contact, water leak) on a microcontroller with
32 KiB of RAM, such as the Silicon Labs EFR32MG22. It is **not a second
stack**: the MAC, NWK, APS, ZDO, ZCL, BDB, security and storage code is
the same as the full stack's, instantiated with smaller tables.

Status in one line: the stack, the sensor logic and the persistent store
fit in 32 KiB with about 9 KiB to spare, measured on an emulated
Cortex-M33; the EFR32MG22 radio (RAIL), flash (MSC) and sleep-mode drivers
do not exist yet and **nothing has run on an EFR32**.

## Architecture

```text
panweave-types   capacity::{Capacity, Cap<N>, VecOf, DequeOf}   type-level table sizes
panweave-mac     MacService<D: MacDims>        FullMac | EndDeviceMac
panweave-nwk     Nwk<C, R, D: NwkDims>         Dims<16,16,4,16> | SleepyEndDevice
panweave-aps     Aps<C, D: ApsDims>            Dims<32,8,8,8>   | EndDevice
panweave-zdo     Zdo<D: ZdoDims>               Dims<4>          | EndDevice
panweave-zcl     Zcl<E, C, A, P: ZclProfile>   Full             | Sensor
panweave-runtime Stack<C, R, S, P: StackProfile, E, CL, A>
                                               FullStack        | SleepySensor
panweave-lite    LiteDevice = Stack<…, SleepySensor, 1, 5, 8> + BDB + ZoneReporter
```

Every generic parameter has the full stack as its default, so
`Stack<C, R, S>`, `ClusterInstance<36>`, `Zcl<2, 12, 36>` and the
`Stack*` aliases mean what they meant before, and a full coordinator and a
Lite sensor are two types of the same generic stack in one binary (the
Lite tests run them together). Profiles are types, not Cargo features:
nothing shrinks behind the back of another crate in the build.

What the profiles change, and only that:

| Layer | Full | Lite (`SleepySensor`) |
|---|---|---|
| ZCL cluster state | `ClusterState`, an enum of every cluster's state (largest: Door Lock, 944 B) | `SensorState`: IAS Zone and Poll Control only (64 B) |
| ZCL attribute entry | 32 B (was 80 B before this work, for every profile) | 32 B |
| ZCL reporting | one slot per attribute | 4 slots per cluster |
| ZCL wide-attribute pool | 384 B per cluster | none; Basic strings are `'static` (flash) |
| Scene table | per endpoint (708 B) | none (`NoScenes`) |
| Endpoints × clusters × attributes | 2 × 12 × 36 | 1 × 5 × 8 |
| NWK neighbours / routes / RDT / BTT | 16 / 16 / 4 / 16 | 2 / 0 / 0 / 4 |
| NWK queues, pending unicasts, broadcast buffers | 16+16, 4, 2 | 8+4, 2, 1 |
| APS keys / bindings / groups / duplicates | 32 / 8 / 8 / 8 | 2 / 2 / 2 / 4 |
| APS queues, pending transmissions | 16+16, 6 | 4+4, 2 |
| MAC TX queue / indirect / queues / power links | 4 / 8 / 8 / 16 | 2 / 0 / 4 / 2 |
| Trust Center tables, virtual devices, touchlink | present | no entries / `NoTouchlink` |
| Persisted record buffer | 512 B | 128 B |

Protocol behaviour is unchanged: a full table answers the way the
specification prescribes for a full table, and every queue overflow is
either impossible at the chosen size (asserted in debug builds) or counted
(the Lite tests assert the counters stay zero).

The sensor (`panweave-lite`):

* `sensor::fill_endpoint` builds the IAS Zone device (DTL 0x0402) in the
  stack's table: Identify, IAS Zone, a 7-attribute battery Power
  Configuration server, optionally Poll Control; the stack adds Basic.
* `sensor::ZoneReporter` publishes the zone status from the inputs
  (Alarm1, Tamper, Battery; Restore notify set; Supervision notify when
  configured), follows each notification's APS outcome
  (`StackEvent::ZoneDelivery`, new in the runtime), retries undelivered
  ones with back-off and at once on rejoin or enrolment, and **holds a
  clear until the alarm it clears was acknowledged** — a failed
  transmission is never reported as "dry".
* `device::LiteDevice` adds the BDB machine, persistence of the IAS
  enrolment (`Kind::Application` 0x0500; a sensor that forgot its CIE
  after a power loss could not report again), and `new_in` for building
  the device in a `static`.
* `power::plan` tells the platform how long and how deeply it may sleep
  (`Awake`, `RamRetained` = EM2, `Off` = EM4 / power loss, which is a
  reset and a restore from flash); `power::EnergyModel` estimates battery
  life from datasheet inputs.

## Memory

Method:

* **Link build** (`examples/lite-probe`, `thumbv8m.main-none-eabihf`,
  opt-level z, fat LTO, `memory-efr32mg22.x`: 32 KiB RAM at 0x20000000):
  the water-leak sensor firmware skeleton with the `LiteDevice` in
  `.bss`, the NOR-flash store and software AES. The link fails when
  `.data` + `.bss` leave less than an 8 KiB stack reserve.
* **QEMU run** (`--features qemu`, `mps2-an505`, Cortex-M33): the same
  sensor in the same 32 KiB, commissioning with a full Panweave
  coordinator (placed in RAM the 32 KiB do not count), reporting a leak,
  losing its parent and rejoining, restarting from its emulated flash.
  Every call into the sensor runs over a painted stack; the deepest use
  is printed. This is a measurement on an emulator, not on an EFR32.
* `scripts/lite_footprint.py` prints the report and checks it against
  `examples/lite-probe/footprint-baseline.json` (CI job
  `lite-footprint`, and `cargo gate` when the target is installed).

Measured 2026-10-29, `dlk` build (Curve25519 key negotiation):

| Component | Before (full stack, the only one) | Lite | Saving |
|---|---:|---:|---:|
| ZCL | 105 384 | 3 464 | 101 920 |
| NWK | 11 320 | 4 464 | 6 856 |
| APS | 11 736 | 3 848 | 7 888 |
| MAC | 4 488 | 1 752 | 2 736 |
| ZDO | 1 912 | 712 | 1 200 |
| BDB | 192 | 192 | 0 |
| Security (inside NWK / APS: two AES key schedules of 352 B each per layer) | — | — | not separated |
| Runtime (rest of the stack: events, handles, TC / DLK / fragmentation tables) | ≈ 6 640 | ≈ 1 690 | ≈ 4 950 |
| Storage in RAM | 4 880 (RAM store of the old probe) | 40 (NOR-flash store) | — |
| **Device (`Node` / `LiteDevice`)** | **148 616** | **16 320** | **132 296** |
| Total static RAM (`.data` + `.bss`) | did not fit 32 KiB | 16 320 | — |
| Peak stack | not measured | 7 000 (264 `main` frame + 6 736 deepest call) | — |
| Complete firmware RAM | — | 23 320 + radio driver | — |
| Flash (`.text` + `.rodata` + vectors) | 164 KiB (old M4F probe, router) | 135 324 | — |

"Before" is the full stack measured with the same Cortex-M33 toolchain at
the start of this work (default profile, `MemoryStorage<32, 128>`; the
runtime row is the `Stack` minus its listed layers). The full stack's own
size did not change (the default profile keeps every table; the compact
attribute entry and the `'static` Basic strings save a little in it too).

Stack peaks per phase (QEMU, octets below the caller): construction 4 828,
initialization 3 064, commissioning with key negotiation 5 816, alarm
report 5 824, parent loss and rejoin 5 268, restart from flash 6 736; per
entry point: `new` 3 068, `initialize` 5 816, `on_radio_frame` 6 736,
`poll` 5 268, `set_inputs` 5 824. Before the stack work in this change the
same run peaked at 24 488 (building the device by value) and 10 184
(restore), which would not have fitted.

Not included, and needed before the 32 KiB figure can be called complete:

* the radio driver (RAIL) and its RAM, and its interrupt stack (no radio
  interrupt runs in the probe);
* a hardware TRNG driver (the probe seeds a test RNG);
* the flash (MSC) driver: reads work, page erase and word write are not
  implemented and fail (`examples/lite-probe/src/flash.rs`).

## Security

The Lite profile removes Trust Center and router state; it removes no
security processing. Applicable to a sleepy end device and kept:
AES-128 CCM* at NWK and APS, MIC verification, incoming frame-counter
replay protection, outgoing frame-counter reservations persisted ahead of
use, the pre-configured or install-code link key, Trust Center link key
update, **dynamic link key negotiation as the initiator** (SPEKE over
Curve25519 with AES-MMO, anonymous or install-code authenticated, with
key verification and the authentication token), secured and Trust Center
rejoin, network key update and switch, APS frame-counter
synchronisation. Not implemented (for any profile): the SHA-256 SPEKE
variant and CBKE (R23 inventory PW-R23-ZDP-016) — a Trust Center that
requires them will not admit the sensor. Ephemeral Curve25519 secrets are
held only for the negotiation and are zeroized by `x25519-dalek`; they
are never persisted.

Two defects found and fixed while testing Lite affect the full stack too:

* A **sleepy joiner** could receive the network key from its parent
  before the Confirm Key of its link-key negotiation; it then dropped the
  NWK-unsecured Confirm Key, the session expired and the joiner restored
  its pre-negotiation key while the Trust Center kept the negotiated one.
  The network key transported under the negotiated key now completes the
  negotiation (`sleepy_joiner_completes_install_code_negotiation`).
* A **failed frame-counter reservation write** left the reservation in
  flight forever and blocked every secured transmission until a reboot.
  It is now abandoned and retried with the next frame; nothing is ever
  secured beyond the committed bound
  (`no_frame_is_secured_beyond_an_uncommitted_counter_reservation`).

## Tests

`cargo test -p panweave-lite`: sensor and power unit tests; four
scenarios against the **full Panweave hub** (join, interview, enrolment,
leak / contact / tamper / battery events, an alarm raised while the hub
is unreachable delivered before its clear, enrolment and network across a
power cycle); twelve against the **full coordinator** (install-code key
negotiation and its refusal with a wrong key, secured rejoin through a
router after parent loss with an alarm raised meanwhile, network key
update, replayed and tampered frames, counter reservation failure,
restart without counter reuse, enrolment write failure, frame loss,
Read Attributes and Configure Reporting through the parent's indirect
queue, rapid input changes, repeated rejoin cycles). Conformance
applicability: `conformance/lite-sleepy-end-device.toml` (rendered into
`docs/conformance.md`). None of this is certification.

## Power

There is no busy loop: the platform sleeps per `LiteDevice::sleep_plan`.
`RamRetained` keeps everything (time must stay monotonic across sleep);
`Off` is only offered off the network with nothing scheduled, and a wake
from it is a reset that restores from flash. A sensor input change is
notified at once (`set_inputs`), not at the next routine report. The
poll interval dominates the energy budget: with the illustrative inputs
of `power::tests` (1.5 µA sleep, 4.5 mA radio, 3 ms per poll), a 7.5 s
poll interval costs several µA on average and a 60 s one under 2 µA; a
CR2032's pulse-current limit and self-discharge must be applied to the
capacity. These are model outputs, not measurements.

## Reproduce

```bash
rustup target add thumbv8m.main-none-eabihf
cargo test -p panweave-lite
cd examples/lite-probe
cargo build --release --features dlk
cp target/thumbv8m.main-none-eabihf/release/panweave-lite-probe target/efr32-dlk.elf
cargo build --release --features qemu,dlk
qemu-system-arm -M mps2-an505 -cpu cortex-m33 -nographic -semihosting-config enable=on,target=native -kernel target/thumbv8m.main-none-eabihf/release/panweave-lite-probe > target/qemu-dlk.log
python ../../scripts/lite_footprint.py target/efr32-dlk.elf --qemu target/qemu-dlk.log --check footprint-baseline.json
```

The contact sensor is the same firmware with `SensorKind::Contact`
(`LiteConfig::new(ieee, SensorKind::Contact)`); the probe builds the
water leak sensor.

## Remaining work

| Item | Severity | Next step |
|---|---|---|
| No EFR32MG22 radio driver | blocks hardware | RAIL adapter behind `panweave_mac::radio` (TX/RX, CCA, auto-ack, address filter, sleep), its RAM and interrupt stack measured |
| No MSC flash driver | blocks hardware | page erase / word write per the reference manual, power-loss tested on a board |
| No TRNG driver | blocks hardware | SE TRNG through `CryptoRng` |
| EM2 / EM4 entry and RTC not implemented | blocks battery life | `power::Platform` for the EFR32 (BURTC deadline, GPIO EM4 wake) |
| Hardware AES not used | RAM / energy | a `BlockCipher` over the SE AES would drop four 352 B key schedules |
| Per-cluster attribute capacity is uniform (8) | ≈ 400 B | Basic and Identify use 5 and 2 of 8 entries |
| Peak stack 6.7 KiB through the receive / pump path | headroom | the APS transmit path copies 440 B pending transmissions; borrow instead |
| 16 KiB parts | stretch | not attempted: the device alone is 16 KiB |
| Measured only on QEMU | evidence | repeat the probe on a board with a stack watermark and a current probe |
