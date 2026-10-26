use std::{env, path::PathBuf};

fn main() {
    // Put the linker script somewhere the linker can find it
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    let libs = [
        "ble_app",
        "btbb",
        "coexist",
        "core",
        "espnow",
        "mesh",
        "net80211",
        "phy",
        "pp",
        "smartconfig",
        "wapi",
        "wpa_supplicant",
        // Panweave: the supplicant is built with WPA3-Personal (SAE) on
        // mbedTLS crypto, which it needs after it (PANWEAVE-PATCH.md).
        "mbedcrypto",
        "printf",
        "regulatory",
    ];

    for lib in libs {
        std::fs::copy(
            format!("libs/lib{}.a", lib),
            out.join(format!("lib{}.a", lib)),
        )
        .unwrap_or_else(|e| panic!("Failed to copy the {lib} library: {e}"));
        println!("cargo:rustc-link-lib={lib}");
    }

    println!("cargo:rustc-link-search={}", out.display());
}
