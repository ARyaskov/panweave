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
> device yet.** Compatibility with the Sber and Yandex devices below is
> unverified until the hardware checklist at the end has been run.

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
| `legacy-joiners` | Admit devices that never complete the Trust Center link key exchange (pre-Zigbee-3.0). Off by default; see [Security](#security) |

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

Factory reset is deliberately not available over the protocol.

## Security

* **Keys**: the network key is generated by the TRNG at formation and never
  leaves the device; it is never logged or sent to the host (the protocol
  has no message carrying a key). Unique Trust Center link keys follow the
  BDB 3.1 policy of the stack (`require_key_exchange` on).
* **Joining**: closed by default; opened only for a bounded window (≤ 254 s)
  by the host or the button; the Trust Center admits new devices only
  during the window plus 30 s.
* **`legacy-joiners`**: turns off `require_key_exchange` so devices that
  never request a unique link key are not removed. Such devices keep the
  well-known global link key: anyone who captures their join learns the
  network key. Enable only if a device needs it, and only while pairing
  it is acceptable.
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
* **Watchdog**: the RTC watchdog resets the chip if the loop stalls for
  10 s.
* **Sizes** (release, `riscv32imac`, measured with `scripts/elf_size.py`):

  | Image | Flash | Static RAM |
  |---|---|---|
  | `hub` | 1 066.2 KiB | 37.0 KiB (32 KiB of it the `esp-radio` heap) |
  | `coordinator` (for comparison) | 1 021.6 KiB | 37.6 KiB |

  The hub engine is about 21 KiB and the session 5 KiB (host measurement,
  `size_of`), on the main stack next to the `Node` (~141 KiB,
  `docs/footprint.md`); the linker leaves about 400 KiB of stack.

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

* **Hardware**: not yet run on a board; no commercial device tested.
* **Stack frame budget**: the stack keeps four unicasts in flight in total
  (`panweave_nwk::layer::PENDING_TX`), and a frame for a sleepy child
  occupies a slot until the child polls. The hub sends one request at a
  time per device and paces frames around IAS enrolment, but with many
  sleepy devices waiting at once, commands can fail with `SendFailed` /
  `Busy` until they poll. Raising `PENDING_TX` is the fix; it is a stack
  change not made here.
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

Nothing about these devices was assumed: no manufacturer names, model
identifiers, endpoints or clusters are hard-coded. Their descriptors are
unknown until interviewed.

| Device | Join | Interview | Reporting | Control | Hardware tested |
|---|---|---|---|---|---|
| Sber water leak sensor | Requires hardware testing | Requires hardware testing | Requires hardware testing | n/a (sensor) | No |
| Yandex water leak sensor | Requires hardware testing | Requires hardware testing | Requires hardware testing | n/a (sensor) | No |
| Sber door/window contact sensor | Requires hardware testing | Requires hardware testing | Requires hardware testing | n/a (sensor) | No |
| Sber E27 smart bulb | Requires hardware testing | Requires hardware testing | Requires hardware testing | Requires hardware testing (On/Off; dimming / color only if its descriptors declare them) | No |
| Simulated IAS water sensor (Auto-Enroll-Request) | Tested in simulation | Tested in simulation | Tested in simulation | n/a | — |
| Simulated IAS contact sensor (Trip-to-Pair) | Tested in simulation | Tested in simulation | Tested in simulation | n/a | — |
| Simulated dimmable light (router) | Tested in simulation | Tested in simulation | Tested in simulation | Tested in simulation | — |

## Hardware verification

Run, for each target device, and record the results (a capture with an
802.15.4 sniffer on the hub's channel makes any deviation diagnosable):

1. Flash the hub with `partitions-hub.csv`; `info` shows `persistent`;
   `network` shows `up`, the PAN and channel.
2. `devices watch` in one terminal; `permit-join 180` in another. Reset the
   device into pairing mode. Expect `joined`, then `interviewed` within a
   minute (sleepy devices may take longer; keep the device awake by
   triggering it during the interview).
3. `device <ieee>`: record manufacturer, model, endpoints, clusters, zone
   type, power source, interview status. A partial interview: note which
   stage (`--verbose` shows the failures).
4. Sensors: trigger leak / dry and open / close; expect exactly one event
   per change. Check `zone-status` for unexpected bits; if Alarm2 or
   another bit carries the state, capture it — that is the evidence an
   `ias::OVERRIDES` entry needs.
5. Battery: `read <ieee> <ep> 0x0001 0x0021` and `0x0020`; wait for a
   battery report (hours).
6. Tamper: open the case if the device has a tamper switch.
7. Bulb: `light <ieee> on`, `off`, `toggle`, `brightness 1`, `50`, `100`;
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
    `command_timeouts`.

Remaining work for verified Sber / Yandex compatibility: run this
checklist per device; add `ias::OVERRIDES` entries only for deviations
captured on air; test whether each device completes the Trust Center
link key exchange (if not, document it and decide on `legacy-joiners`);
measure the sleepy devices' poll intervals and confirm interviews finish
within their awake time; test the bulb as a parent of the sensors
(routing through it).
