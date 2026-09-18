# Panweave on the ESP32-C6 Super Mini

`examples/esp32c6-super-mini` is a bare-metal Rust crate (`no_std`,
`esp-hal` 1.2, `esp-radio` 1.0 beta) that runs a Panweave node on the
ESP32-C6 "Super Mini" board — the small module with a USB-C connector,
GPIO 0–23 around the edge, a blue LED and a BOOT button. It provides
the adapters a real radio needs and four firmware images that show a
Zigbee 4.0 network being formed, joined, bound and used.

## What the crate provides

| Module | What it does |
|---|---|
| `radio` | `Radio`: the stack's `MacAction`s (transmit, channel, addressing, pending list, energy detect) executed on the `esp-radio` 802.15.4 driver; received frames with RSSI / LQI |
| `board` | `Board::init()`: chip at 160 MHz, heap for `esp-radio`, the radio, the on-chip flash as the stack's `Storage`, the TRNG as its `CryptoRng`, the IEEE address from the eFuse MAC (EUI-48 → EUI-64 with `FF FE`), the LED (GPIO 15) and the BOOT button (GPIO 9), the die temperature sensor |
| `runner` | `Runner::step` (poll the stack, run its radio actions, feed it frames until quiet) and `Runner::idle` (wait for the next deadline, a frame or the button); `now()` from the system timer |

The stack's persistent records go through
`panweave_storage::nor_flash::NorFlashStore`, a log-structured store
on any `embedded-storage` NOR flash (two halves of whole sectors,
CRC-checked records, atomic compaction: `panweave-storage` feature
`nor-flash`, unit-tested on the host with a RAM flash). On the board it
occupies the `nvs` partition of espflash's default partition table
(24 KiB at `0x9000`), which a bare-metal image otherwise leaves unused.

### What the radio can and cannot do

`esp-radio` acknowledges received frames and waits for the
acknowledgement of transmitted ones in hardware, filters addresses and
does CCA; `MacService` runs retries, the indirect queue, association
and scanning in software (`Radio::CAPABILITIES`). Three limits of the
driver as of `esp-radio` 1.0.0-beta.1:

* **No energy detection.** There is no ED-scan or RSSI-sampling API,
  so `Radio::energy_detect` reports every channel as quiet and a
  forming coordinator takes the first channel of its primary mask
  (channel 11 by default). Set `Builder::channels` to the channel you
  want.
* **The frame-pending bit is always set** in the acknowledgements the
  hardware sends: a sleepy child of an ESP32-C6 parent polls once more
  than needed after each frame. Never too little, so nothing is lost.
* **Configuration applies at the next transmission or reception
  start.** The driver copies its PIB (channel, PAN ID, addresses,
  auto-ack) into the hardware when it starts a transmission or a
  reception, and it stays in the receive state on its own. `Radio`
  therefore keeps a `dirty` flag and, when the stack's actions end
  without a transmission, sends a frame from this device to itself
  (extended addressing, no acknowledgement request), which every other
  radio filters out. A coordinator changing channel or a joiner
  changing PAN thus sees the change immediately.

The receive buffer format is the ESP-IDF one: octet 0 is the PSDU
length including the FCS, the two FCS octets are replaced by the RSSI
and a status octet; `Radio::receive` strips them and `Radio::transmit`
adds two octets of room for the FCS the hardware appends.

## Building and flashing

```bash
rustup target add riscv32imac-unknown-none-elf
cargo install espflash          # once
cd examples/esp32c6-super-mini
cargo run --release --bin coordinator          # flash + serial monitor
cargo run --release --bin on_off_light
cargo run --release --bin switch
cargo run --release --bin temperature_sensor
```

`.cargo/config.toml` in the crate selects the target, the `linkall.x`
linker script and `espflash flash --monitor` as the runner, so plain
`cargo build --release` also works; the crate is excluded from the
workspace because it builds for another target with its own
dependency tree. Each image is about 1 MiB (the whole device library,
Zigbee stack, `esp-radio` and the console formatting); the stack's RAM
is on the main stack, which the linker gives the ~400 KiB left after
`.bss`.

The features `green-power` (Green Power Basic Proxy on the router) and
`small-tables` (`docs/footprint.md`) are forwarded to the stack.

## The four images

Every image restores its network from flash at boot; a factory-new
device starts commissioning by itself. Everything the node does is
printed on the USB serial console (115200 baud; `espflash monitor`).
The BOOT button is the only input: a short press commissions, holding
it three seconds factory-resets (`Node::factory_reset`: leave, erase
the persisted network, start over).

| Image | Role | Short press |
|---|---|---|
| `coordinator` | Coordinator, Trust Center; an On/Off Light endpoint whose light is the LED | opens the network for 180 s (LED on) and identifies as a finding & binding target |
| `on_off_light` | Router On/Off Light; the LED is the light | off the network: steer; on the network: open it and identify as a target |
| `switch` | rx-on end device On/Off Light Switch | off the network: steer; not bound: finding & binding initiator; bound: Toggle through the binding (LED blinks) |
| `temperature_sensor` | rx-on end device Temperature Sensor reporting the die temperature every 10 s | off the network: steer; on the network: finding & binding initiator |

A walk-through with three boards:

1. Flash `coordinator` on one board. It forms a network on channel 11
   and prints its PAN ID.
2. Flash `on_off_light` on another. Press BOOT on the coordinator
   (network open), then on the light (steering): the light joins;
   both consoles print the join.
3. Flash `switch` on a third. Press BOOT on the coordinator, then on
   the switch: it joins. Press BOOT on the light (it identifies for
   180 s), then on the switch: finding & binding creates a binding for
   On/Off. From now on every press of the switch toggles the light's
   LED.
4. `temperature_sensor` joins the same way; press BOOT on the
   coordinator (it identifies) and then on the sensor: the binding is
   made and the coordinator's console prints a `MeasuredValue` report
   whenever the die temperature moves by 0.5 °C, and every five minutes
   regardless.

The switch's Toggle, the light's `OnOff` event and the sensor's report
are the same calls a host application makes:
`Stack::zcl.send_command(Destination::Bound, …)`, `StackEvent::OnOff`,
`ClusterInstance::attributes.set` with the stack's default reporting.

## Limits of the examples

* The end devices are rx-on (USB-powered); a sleepy end device needs
  the radio and the CPU asleep between polls, which the polled `idle`
  loop does not do (`esp-hal-embassy` timers and `wfi` are the way).
* Any device may join while the coordinator's network is open
  (`TrustCenterPolicy::allow_joins`); a product restricts joins to
  install codes or a joining list.
* No Zigbee Direct: the ESP32-C6 has BLE, but `esp-radio` does not
  support 802.15.4 and BLE at the same time yet.
* Not certified, not interoperability-tested against other vendors'
  stacks on this board; see `docs/conformance.md` for what the stack
  itself implements.
