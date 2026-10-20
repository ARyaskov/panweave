# panweave-esp32c6

Panweave Zigbee 4.0 on the ESP32-C6 Super Mini: the radio, flash, TRNG
and clock adapters (`src/`) and five firmware images (`src/bin/`):
`coordinator`, `on_off_light`, `switch`, `temperature_sensor` and `hub`.

```bash
rustup target add riscv32imac-unknown-none-elf
cargo install espflash
cargo run --release --bin coordinator
```

The guide, the walk-through with three boards and the driver's limits
are in `../../docs/esp32c6.md`. The hub (a standalone Zigbee hub
controlled over USB with `panweave-hub-cli`) has its own partition table,
`partitions-hub.csv`, and guide, `../../docs/esp32c6-hub.md`:

```bash
cargo build --release --bin hub
espflash flash --partition-table partitions-hub.csv target/riscv32imac-unknown-none-elf/release/hub
```
