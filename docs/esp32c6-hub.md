# Panweave hub on the ESP32-C6 Super Mini

The `hub` image of `examples/esp32c6-super-mini` turns an ESP32-C6 Super
Mini (ESP32-C6FH4, 4 MiB flash) into a standalone Zigbee hub: the
coordinator and Trust Center of its own network, which interviews,
monitors and controls third-party Zigbee devices directly — no vendor hub,
no vendor app, no cloud. A computer talks to it over USB with the
**Panweave Hub Protocol v1**; the network keeps running when no computer
is connected.

> **Status.** Everything described here builds, lints and is tested in
> simulation (the real Panweave stack on both sides of a virtual radio).
> **Nothing has been run on an ESP32-C6 board or against a commercial
> device yet.** Compatibility with the Aqara, Sber and Yandex devices below
> is unverified until the hardware checklist at the end has been run.
>
> Bring-up and diagnostics (boot report, trace, counters, radio capture,
> smoke test, hardware-in-the-loop checks) are described in
> [esp32c6-diagnostics.md](esp32c6-diagnostics.md) and
> [esp32c6-hardware-testing.md](esp32c6-hardware-testing.md).

## Contents

1. [Architecture](#architecture)
2. [Building](#building)
3. [Flashing](#flashing)
4. [Connecting over USB and the CLI](#connecting-over-usb-and-the-cli)
5. [The network and commissioning](#the-network-and-commissioning)
6. [Device interview](#device-interview)
7. [Sensors: IAS Zone](#sensors-ias-zone)
8. [Lights](#lights)
9. [Persistent storage](#persistent-storage)
10. [Factory reset and recovery](#factory-reset-and-recovery)
11. [Security](#security)
12. [Panweave Hub Protocol v1](#panweave-hub-protocol-v1)
13. [Reliability and resources](#reliability-and-resources)
14. [Bluetooth LE and Wi-Fi](#bluetooth-le-and-wi-fi)
15. [Limitations](#limitations)
16. [Compatibility matrix](#compatibility-matrix)
17. [Hardware verification](#hardware-verification)

## Architecture

```text
 host application / panweave-hub-cli
        │  Panweave Hub Protocol v1 (COBS + CRC-16 frames)
        │  USB Serial/JTAG (CDC-ACM)
 ┌──────┴──────────────────────────────────────────────────────────┐
 │ ESP32-C6  src/bin/hub.rs — one loop, no RTOS                     │
 │                                                                  │
 │  UsbLink ──► Session ──► Hub (panweave-hub engine) ──► Node      │
 │  (non-blocking   (framing,     registry, interview,     (Panweave │
 │   USB I/O)        access,       IAS Zone, lighting,      stack:    │
 │                   backpressure) commands, persistence)   Coordinator│
 │                                        │                 + TC)     │
 │                         hubdata store ─┘   nvs store ────┘         │
 │                         (registry)          (network, keys,        │
 │                                              frame counters)       │
 │                                                       Radio ───────┼──► 802.15.4
 └──────────────────────────────────────────────────────────────────┘
```

| Piece | Where | Role |
|---|---|---|
| Hub engine | `panweave-hub` (`hub.rs`, `interview.rs`, `registry.rs`, `ias.rs`, `zcl.rs`, `persist.rs`) | Sans-I/O application on the stack: consumes `StackEvent`s, issues ZDP/ZCL requests, tracks transactions with deadlines, keeps the registry, emits protocol events |
| Protocol | `panweave-hub` (`protocol/`, `model.rs`) | Message types, binary encoding, framing — compiled without the stack for host applications (`default-features = false`) |
| Session | `panweave-hub` (`session.rs`) | One host connection: frames in, requests executed with an access check, responses and events out through a bounded queue |
| Hub endpoint | `panweave_hub::hub_endpoint` | Endpoint 1, Combined Interface: client instances of IAS Zone, On/Off, Level Control, Power Configuration, Temperature, Identify, Color Control, Occupancy, Humidity, Illuminance (as many as the stack's endpoint table holds) |
| Board support | `examples/esp32c6-super-mini/src/hub.rs`, `board.rs` | `UsbLink`, `HubStore`, `Watchdog`, `Board::init_hub` (two flash stores sharing one driver) |
| Firmware | `examples/esp32c6-super-mini/src/bin/hub.rs` | Wiring, BOOT button, LED |
| CLI | `panweave-hub-cli` | Development client |

The existing images (`coordinator`, `on_off_light`, `switch`,
`temperature_sensor`) are unchanged in behaviour; `Board` gained the USB
and RTC timer peripherals and a generic storage parameter (defaulting to
the previous type).

## Building

Requirements: Rust 1.95 (the repository pins it in `rust-toolchain.toml`),
the `riscv32imac-unknown-none-elf` target and `espflash`:

```bash
rustup target add riscv32imac-unknown-none-elf
```

```bash
cargo install espflash
```

Build the firmware (the crate selects the target itself):

```bash
cd examples/esp32c6-super-mini
cargo build --release --bin hub
```

Features of the crate that apply to the hub:

| Feature | Effect |
|---|---|
| `small-tables` | Smaller ZCL tables (8 clusters × 24 attributes per endpoint); the hub endpoint then carries fewer client clusters |
| `capture` (default) | Bounded radio frame capture for diagnostics (enables `panweave-hub/radio-capture`), off at run time until an Admin host starts one, sanitized by default ([esp32c6-diagnostics.md](esp32c6-diagnostics.md#radio-capture)) |

Build without capture — the engine then holds no capture buffer and
answers the capture requests `NotSupported`:

```bash
cargo build --release --bin hub --no-default-features
```

The `legacy-joiners` feature of 0.2.0 is gone. It cleared the Trust
Center's `require_key_exchange` flag, which the runtime did not enforce
then; it is enforced now, and the only relaxation is an explicit,
per-device exemption (see [Security](#security)).

The build checks `partitions-hub.csv` against the hub's partition rules
for the 4 MiB flash (`build.rs`) and fails on an overlapping or
misplaced layout; it also stamps the image with the source revision
(`PANWEAVE_BUILD_ID`, `git rev-parse` plus `-dirty`), which the boot
report shows.

Build the CLI (host):

```bash
cargo build --release -p panweave-hub-cli
```

## Flashing

The hub needs its own partition table, which adds the `hubdata` partition
for the device registry:

| Name | Type | Offset | Size | Content |
|---|---|---|---|---|
| `nvs` | data/nvs | `0x9000` | 24 KiB | the stack's records: network, keys, frame counters (same place as every other image) |
| `phy_init` | data/phy | `0xF000` | 4 KiB | kept where the default table has it |
| `factory` | app | `0x10000` | 3 MiB | the firmware (about 1.07 MiB) |
| `hubdata` | data | `0x310000` | 64 KiB | the device registry |

Flash with it (the board in download mode is not needed: the USB
Serial/JTAG resets the chip):

```bash
cd examples/esp32c6-super-mini
espflash flash --partition-table partitions-hub.csv target/riscv32imac-unknown-none-elf/release/hub
```

Do not add `--monitor`: the hub's USB port carries binary protocol frames,
not text. Use the CLI instead.

* Flashing does not erase `nvs` or `hubdata`: a re-flashed hub resumes its
  network and registry. Switching from another image of this crate keeps
  its network too (same `nvs` region) — if that image was a router or an
  end device, factory-reset the hub after the first boot (below).
* Flashed with espflash's default partition table instead, the hub finds
  no `hubdata` partition: it runs with a RAM-only registry, reports
  `persistent: false` in `GetHubInfo`, and writes nothing outside `nvs`.
* Check a modified table before flashing it (no hub needed):

  ```bash
  panweave-hub-cli partitions check examples/esp32c6-super-mini/partitions-hub.csv --image target/riscv32imac-unknown-none-elf/release/hub
  ```

  At boot the hub validates the table it reads from flash with the same
  rules, without writing anything, and reports findings in its boot report.

## Connecting over USB and the CLI

The USB-C connector is the chip's USB Serial/JTAG controller: a CDC-ACM
serial port (`COMx` on Windows, `/dev/ttyACM0` on Linux,
`/dev/cu.usbmodem*` on macOS), USB ID `303a:1001`. The CLI finds it
automatically when it is the only Espressif port; otherwise pass
`--port` or set `PANWEAVE_HUB_PORT`. On Linux the user needs access to
the device (`dialout` / `uucp` group, or a udev rule).

```text
panweave-hub-cli ports
panweave-hub-cli info
panweave-hub-cli network
panweave-hub-cli permit-join 180
panweave-hub-cli devices
panweave-hub-cli devices watch
panweave-hub-cli device 00:12:4b:00:2a:3b:4c:5d
panweave-hub-cli device 00124b002a3b4c5d state
panweave-hub-cli device 00124b002a3b4c5d interview
panweave-hub-cli light 00124b002a3b4c5d on
panweave-hub-cli light 00124b002a3b4c5d off
panweave-hub-cli light 00124b002a3b4c5d toggle
panweave-hub-cli light 00124b002a3b4c5d brightness 50 --transition 10
panweave-hub-cli read 00124b002a3b4c5d 1 0x0500 0x0002
panweave-hub-cli bind 00124b002a3b4c5d 1 0x0001
panweave-hub-cli report 00124b002a3b4c5d 1 0x0001 0x0021 0x20 3600 43200 2
panweave-hub-cli device 00124b002a3b4c5d remove --leave
panweave-hub-cli diagnostics
panweave-hub-cli watch
```

`--timeout SECONDS` changes how long the CLI waits for a response (5 s);
`--verbose` shows dropped frames and unrelated events. The USB
Serial/JTAG resets the chip on the DTR/RTS pattern flashing tools use; the
CLI releases both lines right after opening the port. Whether opening the
port itself can pulse them depends on the host's serial driver — this has
not been checked on hardware. A reset is harmless (the hub resumes its
network and registry) but drops the requests in flight.

## The network and commissioning

* **First boot**: the hub forms a centralized network with a random PAN ID,
  extended PAN ID and network key generated by the chip's TRNG, on
  channel 11 (the driver has no energy detection; see
  `docs/esp32c6.md`). Event `NetworkStarted`.
* **Later boots**: the stack resumes the network from `nvs`, frame counters
  never roll back; event `NetworkRestored`. The registry is restored from
  `hubdata`.
* **A new network is formed only from a clean, empty store.** The boot
  policy (`NetworkRestore::decide`):

  | Stack storage at boot | Network |
  |---|---|
  | holds a network | resumed (`restored`) |
  | empty, no damaged records | a new one is formed (`formed`) |
  | empty, but damaged records were skipped | none: `corrupt-not-formed` |
  | a network that cannot be used: half written (NIB without keys or the reverse), a format from a newer firmware, undecodable | none: `stored-unusable`, plus `network-record-unusable` with the reason |
  | unreadable after 3 attempts | none for now: `read-failed`; read again after 10 s, then at growing intervals up to 5 min (`network-restore-retry`); the network resumes as soon as a read succeeds |

  Every refusal is a Critical trace record. The hub stays up without a
  network (`network` shows `down`) so the host can read the diagnostics;
  forming a new network would silently orphan every paired device, and
  restoring never writes, so the stored keys stay as they were. A storage
  that failed and later reads *empty* is not trusted to be factory new:
  the hub stays without a network. Recovery from a refusal is a
  deliberate factory reset (BOOT for 10 s), after reading the
  diagnostics. Version 0.2.0 formed a new network on a read error, and
  any undecodable network record counted as "empty".
* **Closed by default**: after boot no device can join. The network opens
  for at most 254 s:
  * `PermitJoin { seconds }` (CLI `permit-join`), or
  * a short press of BOOT (180 s). The LED is on while the network is open.

  Opening broadcasts Mgmt_Permit_Joining_req (routers open too) and lets
  the Trust Center hand the network key to new devices; when the window
  closes, the Trust Center keeps accepting new devices for 30 more
  seconds (a device that associated at the last moment still gets its
  key), then stops. `CloseNetwork` closes both at once.
* Devices that rejoin (secured rejoin with the network key, or a Trust
  Center rejoin with their unique link key) are accepted at any time, as
  the Zigbee Trust Center policy prescribes.

## Device interview

When a device joins (Trust Center authorization, then Device_annce) the
hub registers it under its IEEE address and interviews it:

| Stage | Request | Mandatory |
|---|---|---|
| Node descriptor | Node_Desc_req: logical type, receiver-on-when-idle, mains power, manufacturer code | no |
| Active endpoints | Active_EP_req | yes |
| Simple descriptors | Simple_Desc_req per endpoint (up to 4 endpoints, 16 input / 8 output clusters each) | yes |
| Basic attributes | ManufacturerName + ModelIdentifier, then SWBuildID + PowerSource | no |
| IAS Zone | see [Sensors](#sensors-ias-zone) | no |
| Bindings | Bind_req of On/Off, Level Control, Power Configuration, Temperature, Humidity, Occupancy to the hub's endpoint | no |
| Reporting | Configure Reporting of those clusters' attributes | no |
| Initial state | Read of the current state attributes | no |

* Each request has 10 s to be answered (sleepy devices get it when they
  next poll), with up to 3 attempts 2 s apart.
* A **mandatory** stage that runs out of attempts **stalls** the interview
  (`DeviceInterviewFailed`); it resumes automatically the next time the
  device is heard. A device is never declared unsupported because it did
  not answer.
* An **optional** step that runs out of attempts, or that the device
  refuses, is skipped; the interview completes as **partial**. A
  reporting configuration refused with UNSUPPORTED_ATTRIBUTE or
  UNREPORTABLE_ATTRIBUTE is not a failure (the hub asks for every
  attribute it could use).
* At most two devices are interviewed at once; each has one request in
  flight at a time.
* `InterviewDevice` restarts an interview from the beginning.
* The result — endpoints, clusters, category, capabilities, IAS zone,
  interview status — is persisted; `GetDevice` shows it.

**Category and capabilities** come only from what the device declared and
answered: input clusters give On/Off, Level, Color, IAS Zone, Power
Configuration, Temperature, Humidity, Occupancy, Illuminance, Identify,
Poll Control; the IAS ZoneType gives contact, water leak or motion; the
battery capabilities are set only once the device returned a valid
BatteryVoltage / BatteryPercentageRemaining. No manufacturer, model or
device identifier is assumed anywhere. A device the hub cannot classify
stays in the registry as `unknown`, with all its descriptors visible.

## Sensors: IAS Zone

**Enrolment.** For an endpoint serving IAS Zone (0x0500) the interview
reads ZoneState, ZoneType, ZoneStatus and IAS_CIE_Address, writes the
hub's IEEE address as the CIE when it is not already, and then:

* answers a Zone Enroll Request (Auto-Enroll-Request devices send one
  right after the write) with SUCCESS and the zone identifier the hub
  allocated — a request is answered at any time, also outside an
  interview;
* without a request within 5 s, enrols the zone with an unsolicited Zone
  Enroll Response (the Auto-Enroll-Response method, ZCL8 §8.2.2.1.3);
* reads ZoneState back; when the zone is still not enrolled (a response
  lost on its way to a sleepy device), enrols again, up to twice, before
  marking the interview partial.

**Interpretation.** ZoneStatus is interpreted with the meaning ZCL8
Table 8-5 gives the zone's type:

| Zone type | Alarm1 | Alarm2 | Normalized as |
|---|---|---|---|
| Contact switch (0x0015) | first portal open | second portal (not interpreted) | contact open / closed |
| Water sensor (0x002A) | water | not defined (ignored) | water leak / dry |
| Motion sensor (0x000D) | intrusion | presence (not interpreted) | motion |
| any other | — | — | raw ZoneStatus only |

Tamper (bit 2), Battery (bit 3), Trouble (bit 6) and Battery defect
(bit 9) are interpreted for every zone type. While Test (bit 8) is set the
alarm bits are not interpreted. An unknown zone type is never guessed: the
contact / leak state then stays unknown, the raw ZoneStatus is reported.

`panweave_hub::ias::OVERRIDES` can map a specific manufacturer + model to
other alarm bits. It is empty: entries belong there only with a capture of
the device's frames as evidence.

**Events.** Zone Status Change Notifications and ZoneStatus reports
produce, only on a change of the normalized state:

| Water sensor | Contact sensor | Any device |
|---|---|---|
| `WaterLeakDetected`, `WaterLeakCleared`, `WaterLeakStateUnknown` | `ContactOpened`, `ContactClosed`, `ContactStateUnknown` | `BatteryLow`, `TamperDetected`, `DeviceStateChanged` |

Repeated notifications of the same status produce nothing (deduplication
is on the normalized state, so a periodic supervision report is silent).
`BatteryLow` also comes from Power Configuration BatteryAlarmState bit 0;
BatteryPercentageRemaining and BatteryVoltage are reported in the state.

**Unknown state.** The state of a sensor is unknown until it reports or
answers; it becomes unknown again when the device leaves the network
(`…StateUnknown` events) and after a hub reboot (states are not
persisted, so a stale "dry" is never shown as current). The hub reads the
state again as soon as a sleepy device is heard (it polls its parent
then) and right away for mains-powered devices.

## Lights

| Request | Zigbee |
|---|---|
| `LightOn` / `LightOff` / `LightToggle` | On/Off On / Off / Toggle |
| `LightSetBrightness { percent, transition }` | Level Control Move to Level (with On/Off), OptionsMask = OptionsOverride = 0 |

The endpoint is the first one serving the needed cluster unless the
request names one. Brightness requires a Level Control server: the hub
never assumes dimming or color support before the interview found the
clusters.

**Brightness scale.** The application range is 0–100 %. 1–100 % maps
linearly onto Level Control levels 1–254, rounded to the nearest level
(`level = 1 + round((percent − 1) × 253 / 99)`; 50 % is level 126); 0 %
sends Off. Levels map back the same way (`panweave_hub::model::
level_to_brightness`), so a round trip is exact.

**Command stages.** A light command answers `Accepted { command }`, then
ends with an event carrying the furthest stage reached:

| Stage | Meaning |
|---|---|
| `accepted` | the hub took the request |
| `sent` | the stack accepted the frame for transmission |
| `responded` | the device answered (Default Response SUCCESS) |
| `confirmed` | the hub read the resulting On/Off or CurrentLevel back |

A command without answer within 10 s is retried once (On, Off and
brightness are idempotent; Toggle is never retried) and then fails with
`Timeout` at stage `sent`. An error status fails it with `ZclFailure` and
the status. A read-back that times out still completes the command at
`responded`. Reports configured by the interview keep the state current
when the light is switched locally.

Color Control is detected (capability `color`) and readable with
`ReadAttribute`; the protocol has no color commands yet.

## Persistent storage

Two stores share the flash driver, so the hub's data never competes with
the network's:

| Store | Region | Content |
|---|---|---|
| Stack | `nvs`, 0x9000, 24 KiB | network identity, network key, Trust Center link keys, frame-counter reservations, children, bindings (unchanged from the other images) |
| Registry | `hubdata`, 0x310000, 64 KiB | index record + one record per device (≤ 512 octets) |

Both are `panweave_storage::nor_flash::NorFlashStore`: log-structured, two
halves, CRC per record, a record is either old or new after a power loss,
compaction switches halves atomically.

* **Versioned records**: every record starts with a format octet. A
  record of an unknown format is skipped and left untouched (a newer
  firmware's data survives a downgrade); `HubError StorageFailure` with
  the number of skipped devices is reported.
* **Ordering**: a new device's record is written before the index; a
  removed device leaves the index before its record is erased.
* **Wear**: only structural changes are written — join, address change,
  interview progress, removal — coalesced for 2 s and at most two records
  per loop turn. Sensor events, reports, last-seen times and states never
  cause a flash write.
* **Capacity**: 32 devices (`MAX_DEVICES`); a device record is typically
  under 200 octets.
* **Failures are reported**: a failed write (store full or flash I/O
  error) keeps the device in RAM, emits `HubError StorageFailure` once per
  failing period, records `store-failed` in the trace and is retried
  after 30 s; a record that cannot be decoded at boot is skipped and
  recorded (`record-skipped` with its IEEE address). `diagnostics storage`
  shows both stores' free space, writes, compactions, damaged records and
  I/O errors.

## Factory reset and recovery

| Situation | What to do |
|---|---|
| Power loss, reset, watchdog | Nothing: the network and registry resume; sensors read unknown until they report |
| A device misbehaves | `device <ieee> interview` |
| A device was replaced or reset | It rejoins as a known device (same IEEE) or a new one; remove the old entry with `device <ieee> remove` |
| Forget a device but keep it on the network | `device <ieee> remove` (registry only; it is re-registered if it talks again) |
| Remove a device from the network | `device <ieee> remove --leave` (Trust Center Remove Device / NWK Leave, or Mgmt_Leave_req) |
| Start over | Hold BOOT for 10 s: leave, erase `nvs` and the registry, form a new network. Every device must join again |
| Corrupted registry | `espflash erase-region 0x310000 0x10000`, then re-interview devices (the network stays) |
| `network` shows `down` after a reboot | Read `diagnostics system` and `diagnostics storage` first: `read-failed` or `corrupt-not-formed` means the stack's storage could not be used and the hub refused to replace the network. Only then decide on a factory reset |

Factory reset is deliberately not available over the protocol.

## Security

* **Keys**: the network key is generated by the TRNG at formation and never
  leaves the device; it is never logged or sent to the host (the protocol
  has no message carrying a key, and no diagnostic record has a field
  that could hold one). Joiners may request a unique Trust Center link
  key, and the trace records whether they did (`join-tclk-requested`,
  `join-tclk-verified`).
* **The key exchange is required** (`bdbTrustCenterRequireKeyExchange`,
  default on; `panweave_runtime::authorization`). Receiving the network key
  is not authorization:

  | Step | Trust Center state | What the device may do |
  |---|---|---|
  | joins (MAC association, NWK commissioning or rejoin) | policy decision (`join-decision`) | nothing yet |
  | network key delivered | **pending** (`join-key-exchange-pending`), for `bdbTrustCenterNodeJoinTimeout` = 15 s | use the network and the ZDO — what the exchange needs (Node_Desc_req, key negotiation, APS Request / Verify Key, Smart Energy Key Establishment). Its other application frames are dropped by the stack (counted) and the hub neither registers nor interviews it |
  | holds a verified unique Trust Center link key | **authorized** (`join-authorized`) | everything; the hub registers and interviews it |
  | window passed | key-pair entry removed, device asked to leave (`join-key-exchange-timeout`) | nothing |

  Every valid way to the verified key counts: APS Request Key → Transport
  Key → Verify Key (Zigbee 3.0), dynamic link key negotiation with or
  without an install code (R23, verified before the network key is
  sent), Smart Energy CBKE (the key it installs is proven by its own
  confirmation), and Trust Center swap-out renewal. A secured rejoin of an
  authorized device stays authorized; a device that never completed the
  exchange gets a new window when it rejoins. Authorization is derived
  from the persisted key-pair entry, so it survives a reboot — and a
  pending device never becomes authorized by one. Replayed frames are
  rejected by the NWK and APS frame counters; a duplicate Verify Key
  changes nothing. `security` (CLI) shows the policy, pending devices,
  removals, dropped frames and registered devices without access.
* **Application frames are decided on their originator**
  (`Stack::authorize_application_frame`). Every APS data frame outside
  the ZDO — unicast, group or broadcast — is attributed to the device
  that originated it (the NWK source; the key-pair entry of an APS
  secured frame) and admitted only if that device is authorized or an
  admitted exempt device:

  | Originator | Verdict | Counter (`security`) |
  |---|---|---|
  | authorized, or exempt and admitted | delivered | — |
  | IEEE address unknown | held (at most 2 frames, 10 s) while the Trust Center asks for it (IEEE_addr_req); delivered or refused when the answer comes | `unresolved` if never resolved |
  | claimed IEEE address contradicts the address map | refused | `inconsistent` |
  | no key-pair entry (never joined through this Trust Center, removed) | refused | `unknown` |
  | inside its key-exchange window | refused | `pending` |
  | key exchange not completed | refused | `incomplete` |

  Two documented exceptions: Green Power infrastructure frames (GP
  cluster on endpoint 242 or a group: proxies forward them with an alias
  source that belongs to no device) and Smart Energy Key Establishment
  for a pending device (it is how such a device completes the exchange).
  Before v0.3.0 a frame whose source could not be attributed was
  delivered.
* **Legacy devices** (that never request a unique key) are refused by
  default. An administrator can exempt *one device*:
  `security exempt <ieee> --seconds 120` (Admin). The exemption is a
  **single-use commissioning grant**: it waives only the key exchange,
  for that IEEE address, for the first device with that address that
  joins (unsecured, through the Trust Center) within the window — at most
  3600 s, never extended by repeating the request, and not restored by a
  reboot (an unused grant simply ends). The join consumes it and the
  device becomes **admitted** (persisted in its registry record) until
  `security revoke <ieee>`, its removal, or a new unsecured join with its
  address, which withdraws the admission (`join-exemption-withdrawn`) and
  sends the joiner through the normal key exchange. A secured rejoin of
  the admitted device keeps it admitted. At most 8 exemptions; grants
  used and expired are counted. Encryption and MIC checks are never
  relaxed. Caveats: such a device keeps the well-known (or its
  pre-shared) link key, so anyone who captured its join can derive the
  network key; and **an IEEE address is only what the joiner claims** —
  an impostor joining first with the exempted address during the window
  is admitted in its place (tested: `an_exemption_does_not_authenticate_a_claimed_identity`).
  The short, single-use window is the only bound. Exemptions are never
  inferred from manufacturer or model strings or from compatibility
  profiles.
* **Key table**: the Trust Center keys up to 32 devices individually
  (`LINK_KEYS`, 8 with `small-tables`), as many as the registry holds;
  0.2.0 held 8, which would have made the requirement refuse a ninth
  device.
* **Diagnostics**: changing the trace configuration, clearing it, the
  radio capture and exemptions are `Admin`; reading counters, the trace
  and the security status is `Monitor`. Captures are off by default,
  time-limited (≤ 1 h) and sanitized by default: frames keep their
  headers, no payload that could carry a key
  ([esp32c6-diagnostics.md](esp32c6-diagnostics.md#security)).
* **Joining**: closed by default; opened only for a bounded window (≤ 254 s)
  by the host or the button; the Trust Center admits new devices only
  during the window plus 30 s.
* **Frame counters** are reserved in flash before use and never roll back
  across reboots (`docs/storage-model.md`).
* **Trust boundary of USB**: whoever is physically connected to the USB
  port has full access (`Access::Admin`): open the network, control and
  remove devices. The hub cannot tell a legitimate host from another
  program on the same computer — treat the computer as part of the hub.
  The protocol enforces three access levels (`Monitor` < `Control` <
  `Admin`); a future wireless transport must start sessions at `Monitor`
  and raise them only after authenticating the peer.
* **Input validation**: frames are bounded (512-octet bodies), CRC-checked
  and fully decoded before use; malformed, oversized and unknown-version
  messages are rejected with an error code and counted; no raw Zigbee
  frame can be sent through the protocol — `ReadAttribute`,
  `ConfigureReporting` and `Bind` (to the hub only) are the generic
  requests, all read-only or hub-directed.

## Panweave Hub Protocol v1

**Framing.** `0x00 | COBS(body ‖ CRC-16/CCITT-FALSE(body) LE) | 0x00`. A
receiver resynchronizes at any zero octet; damaged frames fail the CRC;
frames over 512 octets of body are discarded without buffering.

**Body.** `version (1) | kind (1 request, 2 response, 3 event) | id
(u16 LE) | tag | fields…`. Integers are little-endian; optional values are
a presence octet and the value; strings and lists are a count octet and
the items. Requests carry a host-chosen id, responses echo it, events
carry a sequence number (gaps reveal loss; `EventsDropped` counts it).
A request of another version is answered `UnsupportedVersion`.

| Request (tag) | Access | Response |
|---|---|---|
| `GetHubInfo` (0x01) | Monitor | `HubInfo`: protocol version, firmware, IEEE, capacity, uptime, persistent |
| `GetNetworkStatus` (0x02) | Monitor | `NetworkStatus`: state, PAN, extended PAN, channel, permit-join seconds, devices |
| `PermitJoin { seconds }` (0x03) | Admin | `Done` |
| `CloseNetwork` (0x04) | Admin | `Done` |
| `ListDevices { start }` (0x05) | Monitor | `DeviceList`: total, start, up to 8 summaries |
| `GetDevice { ieee }` (0x06) | Monitor | `Device`: descriptors, identity, zone, state |
| `InterviewDevice { ieee }` (0x07) | Control | `Done` (progress as events) |
| `GetDeviceState { ieee }` (0x08) | Monitor | `DeviceState` |
| `ReadAttribute` (0x09) | Control | `Accepted` → `CommandCompleted` with the value |
| `ConfigureReporting` (0x0A) | Control | `Accepted` → `CommandCompleted` / `CommandFailed` |
| `Bind` (0x0B) | Control | `Accepted` → … |
| `LightOn` / `LightOff` / `LightToggle` / `LightSetBrightness` (0x0C–0x0F) | Control | `Accepted` → … |
| `RemoveDevice { ieee, leave }` (0x10) | Admin | `Done` |
| `GetDiagnostics` (0x11) | Monitor | `Diagnostics`: radio, stack, registry, storage and link counters |
| `GetBootReport` (0x12) | Monitor | `BootReport`: chip, firmware, build, reset reason, clock, flash, partitions, network outcome |
| `GetRadioDiagnostics` (0x13) | Monitor | `RadioDiagnostics`: driver, MAC, NWK (pending unicasts) and APS counters |
| `GetStorageDiagnostics` (0x14) | Monitor | `StorageDiagnostics`: both stores, registry writes and errors |
| `GetRuntimeDiagnostics` (0x15) | Monitor | `RuntimeDiagnostics`: loop timing, queue use and high-water marks, drops |
| `GetTraceConfiguration` (0x16) | Monitor | `TraceConfiguration` |
| `SetTraceConfiguration` (0x17) | Admin | `TraceConfiguration` |
| `ReadTrace { from, max, ieee }` (0x18) | Monitor | `TracePage` (≤ 12 records) |
| `ClearTrace` (0x19) | Admin | `Done` |
| `StartCapture { seconds, mode }` (0x1A) | Admin | `Done`; `NotSupported` without the `capture` feature. Modes: 1 metadata, 2 sanitized, 3 raw (0 is rejected) |
| `StopCapture` (0x1B) | Admin | `Done` (`NotSupported` without capture) |
| `ReadCapture { max }` (0x1C) | Admin | `CapturePage` (≤ 3 frames, each with its original length) |
| `SetKeyExchangeExemption { ieee, seconds }` (0x1D) | Admin | `Done`; 0 seconds revokes |
| `GetSecurityStatus` (0x1E) | Monitor | `SecurityStatus` (response tag 0x10) |

Requests 0x12–0x1E were added in 0.2.1 after the existing tags; nothing was
renumbered and the 0.2.0 golden frames are unchanged. A 0.2.0 firmware
answers them `UnknownRequest`, which the CLI reports as "firmware does not
support diagnostics". Their responses use tags 0x09–0x10. The same CLI
serves firmware built with and without capture: the capability shows as
`NotSupported`.

**Compatibility across versions.** The protocol version stays 1.

| Change | Versions | Wire effect |
|---|---|---|
| Requests 0x12–0x1E, responses 0x09–0x10 | 0.2.0 → later | appended tags; 0.2.0 frames byte-identical (golden frames). A 0.2.0 host never sends the new tags; a new host talking to 0.2.0 firmware gets `UnknownRequest` |
| `StartCapture` gained its `mode` octet; mode 0 is rejected | unreleased 0.2.1 builds | only between unreleased builds: no released host or firmware has `StartCapture` |
| `SecurityStatus`: `denied` (five counters), `exemptions_used`, `exemptions_expired` after `unauthorized_frames_dropped` | 0.3.0 | changes a response no release has; decoders of an unreleased 0.2.1 build fail on it (`Malformed`) — rebuild the host with the same `panweave-hub` |
| `TargetMetrics`: `radio_tx_idle_ms` renamed `radio_idle_ms` (same position, now TX or RX), `health` and `radio_recoveries` appended | 0.3.0 | same as above |
| Trace codes `stall-suspected` (0x0303), `stall-confirmed` (0x0304), `previous-stall-reset` (0x0305, replacing the unreleased `radio-stalled`), `join-exemption-withdrawn` (0x070e) | 0.3.0 | new codes in existing record fields; an older CLI shows them by number |

Everything changed since 0.2.0 is unreleased, so no released host or
firmware is affected; between builds of this tree, use the CLI and the
firmware from the same commit.

Events: `NetworkStarted`, `NetworkRestored`, `PermitJoinChanged`,
`DeviceJoined`, `DeviceLeft`, `DeviceInterviewCompleted`,
`DeviceInterviewFailed`, `DeviceStateChanged`, `WaterLeakDetected`,
`WaterLeakCleared`, `WaterLeakStateUnknown`, `ContactOpened`,
`ContactClosed`, `ContactStateUnknown`, `BatteryLow`, `TamperDetected`,
`AttributeReport` (attributes the state model does not cover),
`CommandCompleted`, `CommandFailed`, `HubError`, `EventsDropped`.

Error codes: `UnsupportedVersion`, `Malformed`, `UnknownRequest`,
`Unauthorized`, `UnknownDevice`, `Busy`, `NotSupported`,
`InvalidArgument`, `NetworkDown`, `StorageFailure`, `RegistryFull`,
`Timeout`, `ZclFailure`, `ZdoFailure`, `Unreachable`, `SendFailed`.

The definitions are `panweave_hub::protocol`; a Rust host depends on
`panweave-hub` with `default-features = false` (no Zigbee stack). The wire
format is pinned by golden frames in `panweave-hub/tests/hub_protocol.rs`
and fuzzed (`fuzz/fuzz_targets/hub_protocol.rs`).

## Reliability and resources

* **Bounded everything**: registry 32 devices, 10 awaited Zigbee
  transactions (3 ZDP), 8 host commands, 32 queued events, 4 KiB transmit
  queue, 256 octets of USB input per loop turn. Overflow is reported
  (`Busy`, `RegistryFull`, `EventsDropped`, diagnostics counters), never
  silent and never blocking.
* **The radio first**: the loop serves the stack, then at most 256 USB
  octets, then sends what the USB FIFO accepts without waiting. A host that
  is absent or stops reading costs nothing: after 2 s without progress its
  queued output is dropped (a returning host resynchronizes at the next
  frame and sees `EventsDropped`). Responses always have room ahead of
  events.
* **Watchdog and health** (`panweave_hub::supervisor`): the RTC watchdog
  resets the chip if the loop stops for 10 s. The loop feeds it every
  turn unless the health supervisor has *evidence* of a stall:

  | Health | Meaning |
  |---|---|
  | `healthy-idle` | nothing to do; silence is normal (an empty network, only sleepy sensors, no host) |
  | `healthy-active` | frames transmitted or received in the last 60 s |
  | `degraded` | unacknowledged frames, CCA failures, a full queue — the radio still completes frames |
  | `suspected-stall` | the stack's deadline overdue for 10 s, or 5 transmissions handed to the driver that never completed within 30 s while frames wait |
  | `confirmed-stall` | the same evidence 60 s after a recovery |

  A suspected stall is first recovered without side effects: the radio
  configuration is applied again and reception restarted
  (`stall-suspected`, `radio_recoveries`); nothing is written to flash
  and the network is untouched. Only a confirmed stall withholds the
  feed (`stall-confirmed`); its cause is stored first and the next boot
  reports it once (`previous-stall-reset`, Critical). A boot that
  followed a watchdog reset never escalates again — the stall is
  reported and the loop keeps running — so a persistent fault cannot
  become a reset loop. `diagnostics runtime` shows the health and the
  recoveries. The boot report tells a watchdog reset from a power-on,
  software or USB reset.
* **Timing**: a loop turn over 50 ms is recorded (`loop-overrun`), turns
  over 20 ms are counted (`loop_over_20ms`: a sleepy child that polled
  may stop listening before the loop serves its frame), and a radio step
  handles at most 32 received frames before the rest of the loop runs
  (`rx_bursts_cut`). See
  [esp32c6-diagnostics.md](esp32c6-diagnostics.md#timing-and-the-watchdog).
* **Sizes** (release, `riscv32imac`, measured with `scripts/elf_size.py`):

  | Image | Flash | Static RAM |
  |---|---|---|
  | `hub` 0.3.0 (default features, capture) | 1 149.1 KiB | 37.2 KiB (32 KiB of it the `esp-radio` heap) |
  | `hub` 0.3.0 (`--no-default-features`, no capture) | 1 148.3 KiB | 37.2 KiB |
  | `hub` (0.2.1 hardening, capture) | 1 135.2 KiB | 37.1 KiB |
  | `hub` (0.2.1 hardening, no capture) | 1 134.8 KiB | 37.1 KiB |
  | `hub` (0.2.1 before hardening) | 1 122.8 KiB | 37.1 KiB |
  | `hub` (0.2.0) | 1 066.2 KiB | 37.0 KiB |
  | `coordinator` (for comparison) | 1 028.1 KiB | 37.6 KiB |

  Static RAM does not show the engine: the hub engine, the session and
  the `Node` are locals of `main`, on the main stack. Their sizes, measured
  on the host with `size_of` (the ESP32-C6 layout may differ slightly):
  hub engine 28 736 octets with capture, **26 248 without** (the 2 488-octet
  capture buffer is compiled out), session 5 216; the stack's own
  structures grew by about 2.8 KiB with the 32-entry key table. What the
  target actually uses is measured on the target: `diagnostics runtime`
  reports the main stack's watermark and the heap
  ([esp32c6-diagnostics.md](esp32c6-diagnostics.md#target-memory)) — not
  yet observed on hardware.

## Bluetooth LE and Wi-Fi

Investigated in `esp-radio` 1.0.0-beta.1, the version this crate pins:

* The 802.15.4 driver (`esp_radio::ieee802154`) drives the radio PHY
  directly from the application loop and does not take part in
  `esp-radio`'s coexistence arbitration. The `coex` feature of `esp-radio`
  covers Wi-Fi + BLE only (its README's support matrix lists "Coex (Wi-Fi +
  BLE)", nothing for 802.15.4).
* Wi-Fi and BLE run in Espressif's binary blobs and require a preemptive
  scheduler (`esp-rtos`) and a heap; the hub is a single cooperative loop
  built around the 802.15.4 driver's polled interface.
* The ESP32-C6 has one 2.4 GHz radio. ESP-IDF time-slices it between Wi-Fi,
  BLE and 802.15.4 with its coexistence module; no equivalent exists in
  the Rust drivers used here.

Conclusion: **simultaneous Zigbee and BLE, and simultaneous Zigbee and
Wi-Fi, are blocked by the driver.** Neither is implemented, and there is
no placeholder code. A separate BLE provisioning mode (radio switched from
802.15.4 to BLE and back) would stop the Zigbee network while active and
needs `esp-rtos` plus a BLE host stack in the image; it is not
implemented. The application layer does not depend on USB: `Session` takes
bytes from any transport, so a second processor (for example an ESP32-S3
or a Linux board on the hub's UART running the network side) can carry the
same protocol later. Such a transport must authenticate peers before
granting more than `Access::Monitor`. This is not Zigbee Direct, which is a
different, standardized BLE commissioning protocol (`panweave-direct`).

## Limitations

* **Wi-Fi notifications**: an experimental, not yet functional mode;
  see [esp32c6-wifi-alerts.md](esp32c6-wifi-alerts.md) for the
  feasibility assessment and what is implemented.
* **Hardware**: not yet run on a board; no commercial device tested. The
  three v0.3.0 target devices are supported from public documentation
  and simulation only ([device-compatibility.md](device-compatibility.md)).
* **Identities are claims**: an IEEE address, a manufacturer name and a
  model identifier are what a device says. Authorization rests on the
  key exchange; an exemption (and nothing else) admits a device without
  it, for whoever joins first with the exempted address.
* **Exemptions after a factory reset of the device**: a re-paired legacy
  device needs a new exemption only if it was removed; its stored
  exemption follows its IEEE address.
* **Stack frame budget**: the stack keeps four unicasts in flight in total
  (`panweave_nwk::layer::PENDING_TX`), and a frame for a sleepy child
  occupies a slot until the child polls. When the table is full the APS
  layer offers the frame again after 1 s, up to 8 times (about 8 s,
  longer than a held frame can occupy a slot); before v0.3.0 such frames
  were lost, and three sleepy sensors pairing together lost their key
  exchange (simulation: `hub_devices`). With many sleepy devices waiting
  at once, a frame can still fail after its deferrals. `PENDING_TX` is
  unchanged: the failure was the immediate retry, not the slot count.
  `diagnostics radio` shows the table's use, its high-water mark and how
  often it was full.
* **Vendor clusters**: the Aqara sensor's manufacturer-specific cluster
  0xFCC0 (battery voltage among other values) is not read: the hub has
  no client for it. The standard Power Configuration attributes are used.
* **Channel**: formation uses channel 11 (no energy detection in the
  driver).
* **Link quality**: LQI is known only for the hub's direct neighbours (from
  the neighbour table); RSSI per device is not available.
* **Not implemented**: Color Control commands, groups and scenes, OTA
  upgrades, install codes through the protocol, Poll Control fast-poll
  management, Zigbee Green Power devices on the hub, BLE, Wi-Fi.
* **Sleepy devices**: whatever the hub asks a sleeping device waits for its
  next poll; a device polling rarely (minutes) makes interviews and reads
  slow, and stalled interviews resume only when it is heard.

## Compatibility matrix

Generic, standards-based handling covers every device; the compatibility
profiles in `panweave_hub::compat` only recognize a product and correct
how its data is read where evidence shows a deviation. Details, evidence
and fingerprints: [device-compatibility.md](device-compatibility.md).

| Device | Zigbee identity | Join | Interview | Reporting | Hardware tested |
|---|---|---|---|---|---|
| Aqara Water Leak Sensor T1 (WL-S02D, SJCGQ12LM) | `LUMI` / `lumi.flood.agl02` | Verified in simulation (synthetic identity) | Verified in simulation | Verified in simulation (IAS Alarm1) | No — Hardware Test Required |
| Sber opening sensor SBDV-00030 | `_TYZB01_epni2jgy` / `TS0203` | Verified in simulation (synthetic identity) | Verified in simulation | Verified in simulation (IAS Alarm1) | No — Hardware Test Required |
| Yandex water leak sensor YNDX-00527 | `YNDX-00527` | Verified in simulation (synthetic identity) | Verified in simulation | Verified in simulation (IAS Alarm1) | No — Hardware Test Required |
| Sber E27 smart bulb SBDV-00115 | none: Wi-Fi and Bluetooth LE only | out of scope, never paired over Zigbee | — | — | — |
| Simulated IAS water sensor (Auto-Enroll-Request) | — | Tested in simulation | Tested in simulation | Tested in simulation | — |
| Simulated IAS contact sensor (Trip-to-Pair) | — | Tested in simulation | Tested in simulation | Tested in simulation | — |
| Simulated dimmable light (router) | — | Tested in simulation | Tested in simulation | Tested in simulation | — |

"Synthetic identity": the simulator's standard IAS sensor answering with
the product's documented Basic strings. It proves the hub's generic
paths and the profile matching, not the product's behaviour.

## Hardware verification

Start with the automated smoke test and the guided device checks of
[esp32c6-hardware-testing.md](esp32c6-hardware-testing.md)
(`self-test`, `hil light|contact|leak`, and for the v0.3.0 targets
`hil aqara-leak|sber-contact|yandex-leak` with `device <ieee>
fingerprint --json`). Then run, for each target
device, and record the results (`capture export` or an external 802.15.4
sniffer on the hub's channel makes any deviation diagnosable):

1. Flash the hub with `partitions-hub.csv`; `info` shows `persistent`;
   `network` shows `up`, the PAN and channel.
2. `devices watch` in one terminal; `permit-join 180` in another. Reset the
   device into pairing mode. Expect `joined`, then `interviewed` within a
   minute (sleepy devices may take longer; keep the device awake by
   triggering it during the interview).
3. `device <ieee>`: record manufacturer, model, endpoints, clusters, zone
   type, power source, interview status. A partial interview: note which
   stage (`diagnostics interview <ieee>` shows every request, answer,
   timeout and skipped step).
4. Sensors: trigger leak / dry and open / close; expect exactly one event
   per change. Check `zone-status` for unexpected bits; if Alarm2 or
   another bit carries the state, capture it — that is the evidence an
   `ias::OVERRIDES` entry needs.
5. Battery: `read <ieee> <ep> 0x0001 0x0021` and `0x0020`; wait for a
   battery report (hours).
6. Tamper: open the case if the device has a tamper switch.
7. A Zigbee bulb, if one is available (the Sber SBDV-00115 is not a
   Zigbee device): `light <ieee> on`, `off`, `toggle`, `brightness 1`, `50`, `100`;
   each must end `confirmed`. Switch the bulb at the wall and back: the
   bulb rejoins or announces; expect `rejoined` and a state update.
8. Unplug the hub for 10 s and plug it back: the network resumes, devices
   keep working without re-pairing, sensor states read unknown until the
   next report, the bulb's state is read again at once.
9. Close the CLI and trigger sensors; reopen `watch`: the network kept
   running (the bulb still answers), events from the gap are reported as
   dropped if the queue overflowed.
10. `device <ieee> remove --leave`: the device leaves (and usually resets
    itself).
11. `diagnostics`: no `frames_corrupt`, `storage_errors`, unexpected
    `command_timeouts`; `diagnostics export --output run.jsonl` keeps the
    trace with the results.

Remaining work for verified Aqara / Sber / Yandex compatibility: run this
checklist per device; add `ias::OVERRIDES` entries only for deviations
captured on air; test whether each device completes the Trust Center
link key exchange (`security` and the trace show it; a device that does
not is removed after 15 s unless exempted, see [Security](#security));
measure the sleepy devices' poll intervals and confirm interviews finish
within their awake time; test a Zigbee router (a mains-powered bulb or
plug) as a parent of the sensors. A profile's verification status
changes only with a hardware report (`hil … --report`) and a reviewed
code change ([device-compatibility.md](device-compatibility.md)).
