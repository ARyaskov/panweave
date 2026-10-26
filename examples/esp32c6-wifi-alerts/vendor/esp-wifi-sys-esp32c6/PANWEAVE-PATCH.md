# Panweave patch of esp-wifi-sys-esp32c6 0.3.0

This directory is `esp-wifi-sys-esp32c6` 0.3.0 from crates.io (MIT OR
Apache-2.0). It is copied unchanged except for:

1. `libs/libwpa_supplicant.a`: the same supplicant (same ESP-IDF, same
   toolchain) built with WPA3-Personal (SAE) for the station on mbedTLS
   crypto, debug sections stripped. See `../../wpa3-supplicant/README.md` for
   the recipe, provenance, hashes and the reproduction check.
2. `libs/libmbedcrypto.a`: new. It is software-only mbedTLS / TF-PSA-Crypto,
   which the SAE supplicant needs.
3. `build.rs`: links `mbedcrypto` right after `wpa_supplicant`.
4. `src/panweave_stubs.rs`: the two ESP-IDF functions the HMAC-peripheral
   PSA driver in `libmbedcrypto.a` references (`esp_efuse_get_key_purpose`,
   `esp_hmac_calculate`). They always refuse, so no eFuse key can be used.
5. This file.

The closed Wi-Fi libraries (`libnet80211.a`, `libpp.a`, `libcore.a`,
`libcoexist.a`, `libphy.a` and the rest) are the original files.

Used only by `examples/esp32c6-wifi-alerts` through `[patch.crates-io]`.
The normal firmware keeps the crates.io crate.
