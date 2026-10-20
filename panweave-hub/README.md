# panweave-hub

Panweave hub: a Zigbee coordinator and Trust Center application that
manages third-party devices directly — device registry keyed by IEEE
address, device interview, IAS Zone and lighting normalization, host
commands with timeouts and state confirmation, registry persistence —
and the **Panweave Hub Protocol v1** that host applications speak to it.

* Default feature `engine`: the application on top of `panweave-runtime`
  (`no_std`, bounded memory, sans-I/O like the stack).
* Without default features: only the protocol (`protocol`, `model`) —
  message types, binary encoding, COBS + CRC-16 framing — for host
  applications, without the Zigbee stack.

The ESP32-C6 firmware that runs it, the protocol reference, the security
model and the hardware verification checklist are in the repository's
`docs/esp32c6-hub.md`. `panweave-hub-cli` is a development client.

Tested in simulation against simulated devices (`tests/hub_sim.rs`); not
yet verified on hardware or with commercial devices.

Part of [Panweave](https://github.com/ARyaskov/panweave). Panweave is an
independent implementation from the published specifications; it is not
affiliated with, endorsed by, or certified by the Connectivity Standards
Alliance.

Licensed under MIT or Apache-2.0, at your option.
