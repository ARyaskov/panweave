# Radio / MAC hardware abstraction

`panweave-mac` defines the boundary between the Zigbee layers and an
IEEE 802.15.4 radio. Vendor SDKs, RCP transports and the simulator all
implement the same traits; nothing above `panweave-mac` knows which one is in
use.

## Two levels of integration

1. **PHY-level radio** (`Radio` trait): the backend provides raw frame
   TX/RX, channel selection, CCA/ED, and optionally hardware
   auto-acknowledgement and address filtering. Panweave's `MacService`
   implements the MAC behaviours Zigbee needs (sequence numbers, data
   request polling, association handshake, scanning, indirect queueing).
2. **Full MAC** (`MacBackend` trait): the backend already implements an
   802.15.4 MAC (e.g. a vendor SoftMAC or an RCP) and exposes MLME/MCPS-like
   primitives. Panweave maps its needs directly onto them.

Both are `async` traits using `core::future::Future`, so any executor works.

## Requirements the abstraction must satisfy

| Capability | Trait method | Needed by |
|---|---|---|
| Channel page / number | `set_channel` | discovery, formation, frequency agility |
| Active scan (beacon request + beacon collection) | `MacService::active_scan` | join, rejoin, PAN-ID conflict |
| Energy detection scan | `Radio::energy_detect` | formation, network manager |
| Beacon transmission on request | `MacService` (router/coordinator) | join |
| Association / disassociation | `MacService::associate` / `Radio::transmit` | join |
| TX with CSMA-CA, retries, ack request | `Radio::transmit` | all |
| RX with LQI/RSSI/timestamp metadata | `Radio::receive` -> `RxMetadata` | link cost, power control |
| Address and PAN filtering | `Radio::set_address_filter` | all; may be software-emulated |
| Promiscuous mode | `Radio::set_promiscuous` (optional) | sniffer / PCAP tooling |
| Pending-data bit and indirect queue | `MacService::indirect` | parents of sleepy children |
| Data request polling | `MacService::poll_parent` | sleepy end devices |
| Sleep / wake | `Radio::sleep` / `Radio::wake` | sleepy end devices |
| Reset / recovery | `Radio::reset` | error handling |
| Transmit power control | `Radio::set_tx_power` | R23 link power delta |
| Enhanced beacon request / beacon IEs | `frame::ie` | R23 Annex D.11 (optional) |

## What the abstraction deliberately does not include

* Vendor-specific configuration (calibration, antenna diversity).
* Any Zigbee semantics: the MAC layer does not inspect NWK payloads.
* Runtime spawning: the backend is polled by the Panweave runtime.

## Backends

| Backend | Crate | Status |
|---|---|---|
| Simulated medium | `panweave-sim` | reference |
| Loopback / recorded | `panweave-testkit` | reference |
| Host RCP over serial/USB | planned (`panweave-rcp`) | tracked |
| ESP32-C6 (`esp-radio`) | `examples/esp32c6-super-mini` (`docs/esp32c6.md`) | adapter + four firmware images |
| nRF52/nRF54 | example adapter | tracked |
