use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let memory = if env::var_os("CARGO_FEATURE_QEMU").is_some() {
        include_str!("memory-qemu-an505.x")
    } else {
        include_str!("memory-efr32mg22.x")
    };
    fs::write(out.join("memory.x"), memory).unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory-efr32mg22.x");
    println!("cargo:rerun-if-changed=memory-qemu-an505.x");
}
