# Publishing the workspace

Use Rust 1.100 or newer. The commands below use the installed `stable`
toolchain explicitly. Run them from the repository root with a clean Git
working tree and crates.io credentials configured with `cargo login`.

Cargo publishes workspace packages in dependency order. `xtask` is private;
firmware examples and fuzz targets are excluded from the workspace.

First perform the packaging and build verification without uploading:

```powershell
cargo +stable publish --registry crates-io --locked --dry-run -p panweave-runtime -p panweave -p panweave-hub
```

Then publish the same package set:

```powershell
cargo +stable publish --registry crates-io --locked -p panweave-runtime -p panweave -p panweave-hub
```

If the repository's local `target` junction is unavailable, select an
existing writable output location for this shell before either command:

```powershell
$env:CARGO_TARGET_DIR = Join-Path $env:TEMP 'panweave-publish-target'
```

This patch release includes the runtime and facade at 0.5.1 and the hub
at 0.7.1. It includes factory reset fixes, snapshot rotation and durable
alert overflow checkpoints.

Consumers must migrate direct configuration writes to `Stack::config()`
and the dedicated runtime policy methods. A critical `EventQueueLoss`
requires reconstruction and restoration of the affected stack and adapters.
NOR and link-key records retain conservative legacy migration support.

## Remaining validation

Both Cortex-M4F configurations linked successfully. The Cortex-M33 QEMU
scenario completed after fixing the cold-boot flash initialization, with
all five scenario outcomes true and zero reported queue losses. The probe
still needs a stronger assertion that an actual parent-loss/rejoin transition
occurred, rather than only checking the final operating state.

The Cortex-M33 link image uses 16,536 bytes of static RAM and 142,124 bytes
of flash. Its flash footprint exceeds the existing 140,000-byte regression
limit; that limit has not been raised. The measured QEMU peak stack was
7,100 bytes, giving 23,636 bytes of static RAM plus measured stack.

All 13 libFuzzer targets built with the installed nightly and native MSVC
AddressSanitizer. The bounded fuzz execution campaign has not yet run.
These gaps remain open when publishing this snapshot.

See the [Cargo publish reference](https://doc.rust-lang.org/cargo/commands/cargo-publish.html)
for workspace publication and authentication options.
