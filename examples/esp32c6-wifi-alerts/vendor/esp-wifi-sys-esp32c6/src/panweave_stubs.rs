//! Panweave patch (PANWEAVE-PATCH.md): the two ESP-IDF functions that the
//! mbedTLS "HMAC opaque" PSA driver in `libmbedcrypto.a` needs. ESP-IDF
//! compiles that driver unconditionally on chips with an HMAC peripheral
//! (`SOC_HMAC_SUPPORTED`), and the PSA dispatcher references it.
//!
//! The driver only handles keys kept in eFuse for the HMAC peripheral. The
//! WPA3 supplicant never creates such a key, and these stubs make sure none
//! can be used: they always refuse. Nothing touches the peripheral or the
//! eFuses.

/// `ESP_FAIL`.
const ESP_FAIL: i32 = -1;
/// `ESP_EFUSE_KEY_PURPOSE_MAX` on the ESP32-C6: never a valid purpose, so
/// no eFuse key block is ever taken as an HMAC key.
const ESP_EFUSE_KEY_PURPOSE_MAX: u32 = 16;

/// `esp_efuse_purpose_t esp_efuse_get_key_purpose(esp_efuse_block_t)`.
#[no_mangle]
extern "C" fn esp_efuse_get_key_purpose(_block: u32) -> u32 {
    ESP_EFUSE_KEY_PURPOSE_MAX
}

/// `esp_err_t esp_hmac_calculate(hmac_key_id_t, const void *, size_t,
/// uint8_t *)`: always fails, writes nothing.
#[no_mangle]
extern "C" fn esp_hmac_calculate(
    _key_id: u32,
    _message: *const core::ffi::c_void,
    _message_len: usize,
    _hmac: *mut u8,
) -> i32 {
    ESP_FAIL
}
