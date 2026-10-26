# Panweave patch of esp-radio 1.0.0-beta.1

This directory is `esp-radio` 1.0.0-beta.1 from crates.io (MIT OR
Apache-2.0), copied unchanged except for:

1. `build.rs`: the panic "802.15.4 and Wi-Fi won't work together" is kept,
   but skipped when the new feature `panweave-sequential-radio` is
   enabled.
2. `Cargo.toml`: the feature `panweave-sequential-radio = []`.
3. `src/wifi/mod.rs`: `AuthenticationMethodConfig::Wpa3Personal(Password)`
   (added 2026-10-23). The upstream enum has no WPA3 variant, so a
   station could not require WPA3. The new variant maps to
   `WIFI_AUTH_WPA3_PSK`. For a station that value is the scan threshold:
   access points offering less (WPA2, WPA/WPA2, open) are not joined, so
   a WPA2 access point impersonating the network never gets a WPA2
   handshake to attack offline. The password is passed as for WPA2.
   **It cannot join anything with this driver build.** The station side
   of SAE is compiled out of the supplicant blob of
   `esp-wifi-sys-esp32c6` 0.3.0: `sae.c.obj` and `esp_wpa3.c.obj` in
   `libwpa_supplicant.a` hold no code, only their file symbol (checked
   2026-10-23). The `WIFI_ENABLE_WPA3_SAE` feature bit that esp-radio sets
   has no code behind it. A WPA3-only access point is refused with reason
   210 (no access point with compatible security), whatever the
   threshold.
4. `src/wifi/mod.rs`, `apply_sta_config` (added 2026-10-23): with
   `Wpa3Personal` the station is strict. PMF is required (`pmf_cfg.required`)
   and `transition_disable` is set. An access point without PMF is not
   joined. SAE uses hash-to-element when the access point offers it and
   hunt-and-peck otherwise (`sae_pwe_h2e = WPA3_SAE_PWE_BOTH`, the upstream
   value). An H2E-only station was tried on 2026-10-23 and refused (reason
   210) by the target access point, which offers no H2E. Hunt-and-peck is
   the derivation the Dragonblood timing side channels targeted. The
   supplicant here is ESP-IDF 6.1's wpa_supplicant, which carries the
   upstream constant-time mitigations. Other methods are unchanged.
5. This file.

No other driver code is changed. The feature does not make concurrent use work;
it only lets one image contain both drivers. The application
(`examples/esp32c6-wifi-alerts`) must guarantee:

* at most one of `esp_radio::ieee802154::Ieee802154` and
  `esp_radio::wifi::WifiController` is alive at any time;
* `Ieee802154` is dropped only when no transmission is in flight;
* after Wi-Fi is dropped, `Ieee802154` is created again and fully
  reconfigured: Wi-Fi start resets the 802.15.4 MAC and the RF front end.

Why the original guard exists, from the source
(`docs/esp32c6-wifi-alerts.md`, "Feasibility"):

* there is no coexistence arbitration for 802.15.4 in the Rust driver;
* `enable_wifi(false)` and `enable_ieee802154(false)` each gate the shared
  front-end clocks (`clk_fe_*`);
* Wi-Fi initialization pulses a reset of the shared modem, 802.15.4 MAC
  included.

Upstream: <https://github.com/esp-rs/esp-hal>. To refresh, copy the
registry source of the pinned version and re-apply the five changes.
