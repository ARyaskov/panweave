# WPA3-Personal supplicant for the ESP32-C6

How `vendor/esp-wifi-sys-esp32c6/libs/libwpa_supplicant.a` and
`libmbedcrypto.a` were built. The Wi-Fi supplicant that `esp-wifi-sys-esp32c6`
0.3.0 ships is compiled with `CONFIG_ESP_WIFI_ENABLE_WPA3_SAE=n`. Its
`sae.c.obj` and `esp_wpa3.c.obj` hold no code, so a station cannot join a
WPA3 network (reason 210). These two archives are the same supplicant with
SAE, on software mbedTLS.

This applies the recipe of the upstream draft
[esp-wireless-drivers-3rdparty#11](https://github.com/esp-rs/esp-wireless-drivers-3rdparty/pull/11)
(ESP32 only) to the ESP32-C6, with three differences the C6 needs. Its
companions are
[esp-wifi-sys#511](https://github.com/esp-rs/esp-wifi-sys/pull/511) and
[esp-hal#6321](https://github.com/esp-rs/esp-hal/pull/6321).

## Inputs

| What | Version |
|---|---|
| esp-wireless-drivers-3rdparty | `a48a074307ec5467215dd2f8bd42ca809cfe291b` (main, 2026-10-13), plus [`esp-wireless-drivers-3rdparty.patch`](esp-wireless-drivers-3rdparty.patch) |
| ESP-IDF | v6.1-255-g4dbfecac7e3 (`4dbfecac7e3b196d3f6826b3db2fdd5a23708e0d`): the version of the shipped libraries |
| Toolchain | `riscv32-esp-elf` esp-15.2.0_20251204, as installed by `idf_tools.py` for that ESP-IDF |
| Host | Windows 11, Python 3.14, `cargo xtask esp32c6` from PowerShell after `export.ps1` |

## Baseline: the build reproduces the shipped libraries

With the repository's own `patch/esp32c6/sdkconfig.defaults` unchanged,
`cargo xtask esp32c6` in this environment produced libraries byte-identical
to those of `esp-wifi-sys-esp32c6` 0.3.0. That covers `libwpa_supplicant.a`,
`libnet80211.a`, `libregulatory.a`, `libprintf.a` and the copied blobs
(checked 2026-10-23). So the toolchain and sources are those of the shipped
libraries. The SAE build differs only by its configuration, and the ABI
between the supplicant and the closed blobs is unchanged. The closed blobs
of the SAE build are byte-identical to the shipped ones too.

## The patch

[`sdkconfig.defaults`](sdkconfig.defaults) is `patch/esp32c6/sdkconfig.defaults`
after the patch.

* As in #11:
  * `CONFIG_ESP_WIFI_ENABLE_WPA3_SAE=y` and `CONFIG_ESP_WIFI_ENABLE_SAE_H2E=y`;
    `CONFIG_ESP_WIFI_ENABLE_SAE_PK=n`.
  * `CONFIG_ESP_WIFI_MBEDTLS_CRYPTO=y` (SAE requires it).
  * mbedTLS is software only (`CONFIG_MBEDTLS_HARDWARE_{AES,SHA,MPI}=n`) and
    allocates with libc `calloc`/`free` (`CONFIG_MBEDTLS_CUSTOM_MEM_ALLOC=y`).
  * It has no threading layer and no filesystem
    (`CONFIG_MBEDTLS_THREADING_C=n`, `CONFIG_MBEDTLS_FS_IO=n`).
  * `CONFIG_MBEDTLS_SHA1_C=y`.
  * `helper_project/CMakeLists.txt` removes PSA's persistent-key storage
    (NVS).
  * The xtask copies `libmbedcrypto.a`.
* For the C6:
  * `CONFIG_MBEDTLS_HARDWARE_ECC=n`: the C6 has an ECC accelerator, and its
    port needs ESP-IDF clocks and locks.
  * `CONFIG_ESP_TLS_USE_DS_PERIPHERAL=n` and
    `CONFIG_MBEDTLS_HARDWARE_RSA_DS_PERIPHERAL=n`: an ESP-TLS option selects
    the RSA digital-signature peripheral driver, which needs eFuse and
    FreeRTOS.
  * The HMAC-peripheral PSA driver is compiled whatever the configuration
    (`SOC_HMAC_SUPPORTED`). It handles eFuse keys only, which SAE never
    uses. Its two ESP-IDF dependencies are stubs in the vendored crate
    (`src/panweave_stubs.rs`) that always refuse.

## Outputs

`--strip-debug` with `riscv32-esp-elf-strip` (esp-14.2.0) removes the debug
sections only. Code, data and symbols are identical, as compared member by
member.

| Archive | As built (SHA-256) | As vendored, debug stripped (SHA-256) |
|---|---|---|
| `libwpa_supplicant.a` | `1dcd3990733abeed941e17b2784656e3e1720fed01a7c58d0d04bb0ccbd2a3c9` | `3ca57f354abb613e326be57856602448868a83544a12bed59f313fee7dc0a749` |
| `libmbedcrypto.a` | `a48e0e0d41b1d26314f7fd9153d5287d86260cd6fe02e9741ce6eb8479dbec4a` | `3ec0595ccb7e0f0f20c08680f56bc8f58d8128b1ef2727631a5c51e321db6f12` |

Checked in the linked `hub-wifi` image:

* present: `sae_prepare_commit`, `sae_process_commit`, `sae_derive_pt` (H2E),
  `esp_wifi_register_wpa3_cb`, `mbedtls_ecp_mul`;
* absent: hardware-crypto and OS symbols (`aes_hal_*`, `sha_hal_*`,
  `ecc_hal_*`, `gdma_*`, `esp_crypto_*`, `esp_ds_*`, `heap_caps_*`, FreeRTOS
  queues, `pthread_*`, `nvs_*`).

The flash image grows by 118 KiB.

## Initialization outside ESP-IDF

The rebuilt supplicant uses PSA Crypto for HMAC and key import. ESP-IDF
initializes it in `components/mbedtls/port/esp_psa_crypto_init.c` using an
`ESP_SYSTEM_INIT_FN` hook; esp-hal does not execute that hook.
`WifiNetwork::wifi_start` must therefore call `psa_crypto_init()` and check
its status before starting the Wi-Fi controller. Initialization is
idempotent, and attempts are serialized. Without it, PSA key allocation
returns `PSA_ERROR_BAD_STATE`; SAE cannot prepare a commit.

On 2026-10-23, the previous linked image contained `psa_import_key` but
neither `psa_crypto_init` nor `psa_initialize_key_slots`. A board found the
hidden target as WPA3 and failed association with reason 202 in 12–15 ms.
The explicit initialization fix builds and passes release clippy. After
flashing with user permission, a hardware probe successfully joined the
hidden WPA3-Personal target: 891 ms for association and 2414 ms total
downtime, including 1417 ms of diagnostic scans and 95 ms to stop Wi-Fi.
The successful probe used a temporary 10000 ms budget, no BSSID/channel
pin, and the existing password; the budget was subsequently restored to
2000 ms. This probe does not exercise DHCP, TLS or Telegram, or prove a
2000 ms bound. The binary archives themselves have not changed for this
fix.

## Reproduce

```bash
git clone https://github.com/esp-rs/esp-wireless-drivers-3rdparty
```

1. Check out `a48a074307ec5467215dd2f8bd42ca809cfe291b` and apply
   `esp-wireless-drivers-3rdparty.patch`.
2. Clone ESP-IDF at `4dbfecac7e3b196d3f6826b3db2fdd5a23708e0d` with its
   submodules. Run `idf_tools.py install --targets esp32c6` and
   `install-python-env`, then `export.ps1` (or `export.sh`).
3. Run `cargo xtask esp32c6` in the 3rdparty checkout. The outputs are in
   `libs/esp32c6/`.
4. Compare with the table above.

## Licenses

* The supplicant is wpa_supplicant (BSD) with Espressif's port (Apache-2.0).
* mbedTLS and TF-PSA-Crypto are Apache-2.0 OR GPL-2.0-or-later, used here
  under Apache-2.0.
* esp-wireless-drivers-3rdparty is Apache-2.0, esp-wifi-sys is MIT OR
  Apache-2.0, and the Espressif Wi-Fi libraries (esp32-wifi-lib) are
  Apache-2.0.
* All are compatible with this project's MIT OR Apache-2.0. The changes to
  each are listed here and in `vendor/*/PANWEAVE-PATCH.md`.
