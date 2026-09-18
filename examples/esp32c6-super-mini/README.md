# panweave-esp32c6

Panweave Zigbee 4.0 on the ESP32-C6 Super Mini: the radio, flash, TRNG
and clock adapters (`src/`) and four firmware images (`src/bin/`):
`coordinator`, `on_off_light`, `switch`, `temperature_sensor`.

```bash
rustup target add riscv32imac-unknown-none-elf
cargo install espflash
cargo run --release --bin coordinator
```

The guide, the walk-through with three boards and the driver's limits
are in `../../docs/esp32c6.md`.
