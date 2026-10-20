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

This is a development utility, not the desktop application. The guide is
`docs/esp32c6-hub.md` in the repository.

Licensed under MIT or Apache-2.0, at your option.
