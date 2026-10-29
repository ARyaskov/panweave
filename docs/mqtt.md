# MQTT and Home Assistant

`panweave-mqtt` puts the devices of a Panweave hub on an MQTT broker and
announces them to Home Assistant through
[MQTT discovery](https://www.home-assistant.io/integrations/mqtt/#mqtt-discovery).
It runs on a host next to the hub (a PC, a Raspberry Pi) and talks to the
hub over USB serial with the Panweave Hub Protocol, like
`panweave-hub-cli`. The hub firmware is unchanged.

```text
ESP32-C6 hub ──USB── panweave-mqtt ──MQTT── broker ── Home Assistant
```

## Running it

```bash
cargo run --release -p panweave-mqtt -- --broker 127.0.0.1:1883
```

| Option | Default | Meaning |
|---|---|---|
| `--port PORT` | `PANWEAVE_HUB_PORT`, else the only Espressif USB port | the hub's serial port |
| `--broker HOST:PORT` | `127.0.0.1:1883` | MQTT broker |
| `--username NAME` | none | broker user |
| `--password-env VAR` | none | read the broker password from environment variable `VAR` |
| `--client-id ID` | `panweave-mqtt` | MQTT client identifier |
| `--base-topic T` | `panweave` | prefix of the bridge's topics |
| `--discovery-prefix P` | `homeassistant` | Home Assistant's discovery prefix |
| `--group N=NAME` | none | offer group `N` (1–0xfff7, decimal or `0x` hex) as a light; repeatable |
| `--no-admin` | admin on | ignore the network requests (`bridge/request/…`) |
| `--verbose` | off | log every publication |

The password never appears on the command line or in the logs. The MQTT
connection is plain TCP (MQTT 3.1.1, QoS 0): run the broker on the same
host, or reach a remote one through a TLS tunnel. Both connections are
re-established when they drop; after a reconnection the bridge reads the
hub's registry again.

## What Home Assistant gets

One Home Assistant device per Zigbee device, linked to a "Panweave hub"
device (with a **Permit join** switch), with entities chosen from the
interview's category and capabilities:

| Capability | Entity |
|---|---|
| lights (On/Off, Level) | `light`, JSON schema, brightness in percent |
| colour lights (Color Control) | the same `light` with the colour modes the light reports (`color_temp`, `xy`, else `hs`) and its mired range |
| other On/Off outputs | `switch` |
| contact | `binary_sensor`, class `door` |
| water leak | `binary_sensor`, class `moisture` |
| occupancy / motion | `binary_sensor`, class `motion` |
| IAS Zone | `binary_sensor` tamper and battery-low (diagnostic) |
| temperature, humidity | `sensor` (°C, %) |
| battery percentage, voltage | `sensor` (%, mV; diagnostic) |

Each `--group` is a further `light` on the hub's device. A group command
is one group-addressed frame: nothing confirms it, so the group light is
optimistic; the members' own entities show what they did.

## Topics

`<base>` is `--base-topic`, `<id>` a device's IEEE address as `0x` and
16 hex digits.

| Topic | Direction | Payload |
|---|---|---|
| `<base>/bridge/state` | out, retained | `online` / `offline` (MQTT last will) |
| `<base>/bridge/permit_join` | out, retained | `ON` / `OFF` |
| `<base>/bridge/log` | out | `{"level", "message"}` |
| `<base>/bridge/request/permit_join` | in | seconds (0 closes), `ON` (254 s), `OFF`, or `{"time"}` |
| `<base>/bridge/request/remove` | in | device id, or `{"id", "force"}` (`force`: registry only, no Leave) |
| `<base>/bridge/request/interview` | in | device id |
| `<base>/bridge/request/install_code` | in | `{"id", "code"}`: the install code in hex with its CRC (never logged) |
| `<base>/bridge/request/group_add`, `group_remove` | in | `{"id", "group"}` |
| `<base>/bridge/request/scene_store` | in | `{"id", "group", "scene"}`: the device's current state becomes the scene |
| `<base>/bridge/request/scene_recall` | in | `{"group", "scene", "transition"}` |
| `<base>/group/<n>/set` | in | as `<base>/<id>/set`, to the members of group `n` (configured with `--group`) |
| `<base>/<id>` | out, retained | the state object |
| `<base>/<id>/availability` | out, retained | `online` / `offline` |
| `<base>/<id>/set` | in | `{"state": "ON"/"OFF"/"TOGGLE", "brightness": 0–100, "color_temp": mireds, "color": {"x", "y"} or {"h", "s"}, "transition": seconds}`, or `ON` / `OFF` / `TOGGLE` |
| `<base>/<id>/event` | out | `{"event"}`: `contact-opened`, `water-leak-detected`, `battery-low`, … |
| `<base>/<id>/attribute` | out | an attribute report the state model does not cover |
| `<base>/<id>/ota` | out | `{"state": "downloading", "progress"}`, then `upgrading` or `failed` with the device's `status` |
| `<discovery>/status` | in | `online`: Home Assistant restarted; everything is republished |

The state object always carries every field, `null` when unknown:

```json
{"state": "ON", "brightness": 40, "open": null, "water_leak": null,
 "occupancy": null, "tamper": null, "battery_low": null, "trouble": null,
 "battery": null, "voltage": null, "temperature": null, "humidity": null,
 "zone_status": null}
```

A colour light adds `color_mode` (`color_temp`, `xy` or `hs`),
`color_temp` (mireds) and `color` (`x`, `y` in 0–1; `h` in degrees, `s`
in percent, when the light reports hue and saturation).

OTA upgrades are run with `panweave-hub-cli ota update`, which serves
the image; the hub's serial port has one client at a time, so stop the
bridge meanwhile.

## Availability

* A device is online while it is heard (state changes, reports, command
  answers). A device that left, or was removed, is withdrawn: its
  retained discovery, state and availability messages are cleared.
* A mains-powered device silent for 10 minutes is checked with a read of
  its Basic cluster; a failed read marks it offline.
* A battery device silent for 25 hours is marked offline, without a
  check (it would wait for its next poll anyway).

## Access

The hub trusts the USB link with full access. Through the bridge, anyone
who can publish on `<base>/…` controls the devices, and on
`<base>/bridge/request/…` opens the network and removes devices. Protect
the broker with users and ACLs, or start the bridge with `--no-admin`.

## Status

Tested with the hub engine in the simulator (`panweave-mqtt/tests`), the
MQTT packets with unit tests. Not yet run against a broker and Home
Assistant installation in this repository's tests.
