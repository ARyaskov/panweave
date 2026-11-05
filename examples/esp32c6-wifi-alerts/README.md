# esp32c6-wifi-alerts (frozen)

> **Frozen experimental snapshot**, kept for reference. It is not developed
> further in this repository.

The Panweave hub image of [`../esp32c6-super-mini`](../esp32c6-super-mini)
built as `hub-wifi`, with the board crate's `wifi-alerts` feature: the one
radio of the ESP32-C6 is lent from IEEE 802.15.4 to Wi-Fi for a short window
to send a notification, then given back to Zigbee (`panweave_hub::alert`,
`src/wifi_switch.rs` of the board crate).

Contents:

* `vendor/esp-radio`: esp-radio 1.0.0-beta.1 with the "802.15.4 and Wi-Fi"
  build guard skipped under the feature `panweave-sequential-radio`
  (`PANWEAVE-PATCH.md`); the two drivers are never alive at the same time.
* `vendor/esp-wifi-sys-esp32c6`: the Wi-Fi blobs with a WPA3-Personal (SAE)
  station supplicant; `wpa3-supplicant/` is the recipe.
* `src/bin/wifi-scan-check.rs`: a Wi-Fi reception diagnostic.

The normal `hub` image of `esp32c6-super-mini` does not depend on any of
this.

Build from this directory: `cargo build --release --bins`.
