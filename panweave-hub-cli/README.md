# panweave-hub-cli

A development and test client for the Panweave hub over its USB serial
port, speaking the Panweave Hub Protocol v1 with the message definitions
of `panweave-hub` (no duplicated structures).

```bash
cargo run --release -p panweave-hub-cli -- info
cargo run --release -p panweave-hub-cli -- permit-join 180
cargo run --release -p panweave-hub-cli -- devices watch
cargo run --release -p panweave-hub-cli -- light 00124b002a3b4c5d brightness 50
```

Run it without arguments for the command list. The serial port is found
automatically (Espressif USB VID 0x303a) or given with `--port` /
`PANWEAVE_HUB_PORT`. Works on Windows, Linux and macOS through the
`serialport` crate (built without `libudev`).

Bring-up and diagnostics (firmware 0.2.1 or later; older firmware
reports the requests as unsupported):

```bash
cargo run --release -p panweave-hub-cli -- self-test
cargo run --release -p panweave-hub-cli -- diagnostics system
cargo run --release -p panweave-hub-cli -- diagnostics interview 00124b002a3b4c5d
cargo run --release -p panweave-hub-cli -- security
cargo run --release -p panweave-hub-cli -- capture export --output air.pcap --seconds 60
cargo run --release -p panweave-hub-cli -- partitions check partitions-hub.csv
```

Device compatibility (`docs/device-compatibility.md`): the identifying
values of a device with their provenance, and the guided checks of the
v0.3.0 target devices:

```bash
cargo run --release -p panweave-hub-cli -- device 54ef4410xxxxxxxx fingerprint --json
cargo run --release -p panweave-hub-cli -- hil aqara-leak 54ef4410xxxxxxxx --report aqara.json
```

Captures are sanitized by default (frame headers only); `--mode raw`
needs `--allow-raw`. `--json` gives machine-readable output; exit codes are 0 (success),
1 (failure), 2 (usage) and 3 (hub unreachable).

This is a development utility, not the desktop application. The guides
are `docs/esp32c6-hub.md`, `docs/esp32c6-diagnostics.md` and
`docs/esp32c6-hardware-testing.md` and `docs/device-compatibility.md` in
the repository.

Licensed under MIT or Apache-2.0, at your option.
