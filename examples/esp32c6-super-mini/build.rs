//! Build-time checks and metadata for the firmware images.
//!
//! * `partitions-hub.csv` must pass the hub's partition validation for the
//!   board's 4 MiB flash (the same checks the firmware runs at boot and
//!   `panweave-hub-cli partitions check` runs on a host): a layout that
//!   would overlap, leave the flash or move the stack's `nvs` region fails
//!   the build instead of a field device.
//! * `PANWEAVE_BUILD_ID` is set to the source revision (`git rev-parse`,
//!   `-dirty` with local changes) unless the environment already sets it,
//!   and to `unknown` without git. The hub reports it in its boot report.
//! * The esp-hal linker script `linkall.x`, passed here rather than in
//!   `.cargo/config.toml` rustflags, which a `RUSTFLAGS` environment
//!   variable (CI sets one) replaces entirely.

use std::process::Command;

/// Flash size of the ESP32-C6FH4 on the Super Mini.
const FLASH_SIZE: u32 = 0x40_0000;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn main() {
    println!("cargo:rustc-link-arg=-Tlinkall.x");
    println!("cargo:rerun-if-changed=partitions-hub.csv");
    println!("cargo:rerun-if-env-changed=PANWEAVE_BUILD_ID");
    let csv = std::fs::read_to_string("partitions-hub.csv").expect("partitions-hub.csv");
    let table = match panweave_hub::partitions::parse_csv(&csv) {
        Ok(t) => t,
        Err(e) => panic!("partitions-hub.csv line {}: {}", e.line, e.what),
    };
    let findings = panweave_hub::partitions::validate(&table, FLASH_SIZE, None);
    for f in &findings {
        println!(
            "cargo:warning=partitions-hub.csv: {} (partition {:?})",
            f.describe(),
            f.partition()
        );
    }
    assert!(
        !findings.iter().any(|f| f.is_fatal()),
        "partitions-hub.csv is not a valid hub layout"
    );

    if std::env::var("PANWEAVE_BUILD_ID").is_err() {
        let id = match git(&["rev-parse", "--short=12", "HEAD"]) {
            Some(rev) => {
                let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
                    .is_some_and(|s| !s.is_empty());
                if dirty { format!("{rev}-dirty") } else { rev }
            }
            None => "unknown".to_string(),
        };
        println!("cargo:rustc-env=PANWEAVE_BUILD_ID={id}");
        if let Some(head) = git(&["rev-parse", "--git-path", "HEAD"]) {
            println!("cargo:rerun-if-changed={head}");
        }
    }
}
