# panweave-mqtt

The devices of a Panweave hub on an MQTT broker, announced to Home
Assistant through MQTT discovery. Runs on a host next to the hub and
speaks the Panweave Hub Protocol over USB serial.

```bash
cargo run --release -p panweave-mqtt -- --broker 127.0.0.1:1883
```

Options, topics, the state object and availability rules:
[`docs/mqtt.md`](../docs/mqtt.md).
