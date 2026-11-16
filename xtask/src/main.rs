//! Repository automation for Panweave.
//!
//! Sub-commands:
//!
//! * `conformance [--check]` — render `docs/conformance.md` from
//!   `conformance/*.toml` and verify that every referenced test exists.
//! * `codegen [--check]` — render `panweave-device-library/src/generated.rs`
//!   from `panweave-device-library/metadata/devices.toml`.
//! * `gate [--require-no-std]` — run the shared local/CI quality gate
//!   (fmt, check, clippy, tests, fuzz target checks, no_std builds,
//!   conformance and codegen checks).

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Inventory {
    document: String,
    title: String,
    #[serde(default)]
    requirement: Vec<Requirement>,
}

#[derive(Debug, Deserialize)]
struct Requirement {
    id: String,
    section: String,
    summary: String,
    level: String,
    status: String,
    module: String,
    #[serde(default)]
    tests: Vec<String>,
    #[serde(default)]
    notes: String,
}

const STATUSES: &[&str] = &[
    "implemented",
    "partially-implemented",
    "not-implemented",
    "not-applicable",
    "requires-hardware-validation",
    "requires-clarification",
];

const LEVELS: &[&str] = &[
    "mandatory",
    "optional",
    "conditional",
    "deprecated",
    "informative",
];

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .expect("xtask lives one level below the workspace root")
        .to_path_buf()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("conformance") => conformance(args.iter().any(|a| a == "--check")),
        Some("codegen") => codegen(args.iter().any(|a| a == "--check")),
        Some("gate") => gate(args.iter().any(|a| a == "--require-no-std")),
        _ => {
            eprintln!(
                "usage: cargo xtask <conformance [--check] | codegen [--check] | gate [--require-no-std]>"
            );
            Err("unknown sub-command".to_string())
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn load_inventories(root: &Path) -> Result<Vec<(String, Inventory)>, String> {
    let dir = root.join("conformance");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .map_err(|e| format!("reading {}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    files.sort();
    let mut out = Vec::new();
    for path in files {
        let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let inv: Inventory =
            toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        out.push((name, inv));
    }
    Ok(out)
}

#[derive(Deserialize)]
struct WorkspaceManifest {
    workspace: WorkspaceMembers,
}

#[derive(Deserialize)]
struct WorkspaceMembers {
    members: Vec<String>,
}

#[derive(Deserialize)]
struct PackageManifest {
    package: PackageName,
}

#[derive(Deserialize)]
struct PackageName {
    name: String,
}

fn read_manifest<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let source = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    toml::from_str(&source).map_err(|e| format!("{}: {e}", path.display()))
}

fn source_names(text: &str, package: &str, names: &mut Vec<String>) {
    let mut pending_test = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("#[test]") || line.starts_with("#[tokio::test") {
            pending_test = true;
            continue;
        }
        if !pending_test {
            continue;
        }
        if let Some(rest) = line
            .strip_prefix("fn ")
            .or_else(|| line.strip_prefix("async fn "))
        {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                names.push(format!("{package}::{name}"));
                names.push(name);
            }
            pending_test = false;
        } else if !line.starts_with("#[") && !line.is_empty() && !line.starts_with("//") {
            pending_test = false;
        }
    }
}

fn walk_test_sources(dir: &Path, package: &str, names: &mut Vec<String>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        // Never descend into private metadata, build output, dependencies
        // or linked directories outside the selected workspace sources.
        if name.starts_with('.') || matches!(name.as_ref(), "target" | "vendor" | "node_modules") {
            continue;
        }
        let path = entry.path();
        let kind = entry
            .file_type()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            walk_test_sources(&path, package, names)?;
        } else if kind.is_file() && path.extension().is_some_and(|x| x == "rs") {
            let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            source_names(&text, package, names);
        }
    }
    Ok(())
}

/// Collects test names only from source and test directories of explicit
/// Cargo workspace members. Excluded examples, metadata and linked trees
/// cannot accidentally satisfy conformance references.
fn collect_test_names(root: &Path) -> Result<Vec<String>, String> {
    let manifest: WorkspaceManifest = read_manifest(&root.join("Cargo.toml"))?;
    let mut names = Vec::new();
    for member in manifest.workspace.members {
        let relative = Path::new(&member);
        if relative.components().any(|component| {
            !matches!(component, std::path::Component::Normal(name) if !name.to_string_lossy().starts_with('.'))
        }) {
            return Err(format!("workspace member must be a local source directory: {member}"));
        }
        let dir = root.join(relative);
        if fs::symlink_metadata(&dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?
            .file_type()
            .is_symlink()
        {
            return Err(format!(
                "workspace member cannot be a linked directory: {member}"
            ));
        }
        let package: PackageManifest = read_manifest(&dir.join("Cargo.toml"))?;
        for sources in ["src", "tests"] {
            let path = dir.join(sources);
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                    walk_test_sources(&path, &package.package.name, &mut names)?;
                }
                Ok(_) => return Err(format!("{} is not a source directory", path.display())),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("{}: {error}", path.display())),
            }
        }
    }
    names.sort();
    names.dedup();
    Ok(names)
}

fn conformance(check: bool) -> Result<(), String> {
    let root = workspace_root();
    let inventories = load_inventories(&root)?;
    let tests = collect_test_names(&root)?;
    let mut errors = Vec::new();
    let mut ids = std::collections::HashSet::new();

    let mut md = String::new();
    md.push_str("# Conformance status\n\n");
    md.push_str(
        "Generated by `cargo xtask conformance` from `conformance/*.toml`. Do not edit by hand.\n\n",
    );
    md.push_str(
        "Panweave is an independent implementation; this table records the maintainers' own \
         assessment against the referenced specification sections and is not a certification claim.\n\n",
    );

    let mut totals: BTreeMap<String, usize> = BTreeMap::new();
    let mut summary_rows = Vec::new();

    for (name, inv) in &inventories {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for r in &inv.requirement {
            if !STATUSES.contains(&r.status.as_str()) {
                errors.push(format!(
                    "{name}: {} has invalid status {:?}",
                    r.id, r.status
                ));
            }
            if !LEVELS.contains(&r.level.as_str()) {
                errors.push(format!("{name}: {} has invalid level {:?}", r.id, r.level));
            }
            if !ids.insert(r.id.clone()) {
                errors.push(format!("duplicate requirement id {}", r.id));
            }
            if r.status == "implemented" && r.tests.is_empty() {
                errors.push(format!(
                    "{name}: {} is marked implemented but lists no tests",
                    r.id
                ));
            }
            for t in &r.tests {
                if !tests.iter().any(|n| n == t) {
                    errors.push(format!("{name}: {} references unknown test {t}", r.id));
                }
            }
            *counts.entry(r.status.clone()).or_default() += 1;
            *totals.entry(r.status.clone()).or_default() += 1;
        }
        summary_rows.push((inv.document.clone(), inv.title.clone(), counts));
    }

    md.push_str("## Summary\n\n| Document | Total | Implemented | Partial | Not implemented | N/A | HW validation | Clarification |\n|---|---|---|---|---|---|---|---|\n");
    for (doc, _title, counts) in &summary_rows {
        let get = |k: &str| counts.get(k).copied().unwrap_or(0);
        let total: usize = counts.values().sum();
        md.push_str(&format!(
            "| {doc} | {total} | {} | {} | {} | {} | {} | {} |\n",
            get("implemented"),
            get("partially-implemented"),
            get("not-implemented"),
            get("not-applicable"),
            get("requires-hardware-validation"),
            get("requires-clarification"),
        ));
    }
    {
        let get = |k: &str| totals.get(k).copied().unwrap_or(0);
        let total: usize = totals.values().sum();
        md.push_str(&format!(
            "| **All** | {total} | {} | {} | {} | {} | {} | {} |\n\n",
            get("implemented"),
            get("partially-implemented"),
            get("not-implemented"),
            get("not-applicable"),
            get("requires-hardware-validation"),
            get("requires-clarification"),
        ));
    }

    for (_name, inv) in &inventories {
        md.push_str(&format!("## {} — {}\n\n", inv.document, inv.title));
        md.push_str("| Id | Section | Level | Status | Module | Summary | Tests | Notes |\n|---|---|---|---|---|---|---|---|\n");
        for r in &inv.requirement {
            let tests = if r.tests.is_empty() {
                "—".to_string()
            } else {
                r.tests
                    .iter()
                    .map(|t| format!("`{t}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            md.push_str(&format!(
                "| {} | {} | {} | {} | `{}` | {} | {} | {} |\n",
                r.id,
                r.section.replace('|', "\\|"),
                r.level,
                r.status,
                r.module,
                r.summary.replace('|', "\\|"),
                tests,
                r.notes.replace('|', "\\|"),
            ));
        }
        md.push('\n');
    }

    if !errors.is_empty() {
        for e in &errors {
            eprintln!("conformance: {e}");
        }
        return Err(format!("{} conformance inventory error(s)", errors.len()));
    }

    let out = root.join("docs").join("conformance.md");
    if check {
        let existing = fs::read_to_string(&out).unwrap_or_default();
        if existing.replace("\r\n", "\n") != md {
            return Err("docs/conformance.md is out of date; run `cargo xtask conformance`".into());
        }
        println!("conformance: up to date ({} requirements)", ids.len());
    } else {
        fs::write(&out, md).map_err(|e| format!("writing {}: {e}", out.display()))?;
        println!(
            "conformance: wrote {} ({} requirements)",
            out.display(),
            ids.len()
        );
    }
    Ok(())
}

fn run(root: &Path, program: &str, args: &[&str]) -> Result<(), String> {
    println!("$ {program} {}", args.join(" "));
    let status = Command::new(program)
        .args(args)
        .current_dir(root)
        .status()
        .map_err(|e| format!("spawning {program}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} {} failed with {status}", args.join(" ")))
    }
}

fn gate(require_no_std: bool) -> Result<(), String> {
    let root = workspace_root();
    run(&root, "cargo", &["fmt", "--all", "--check"])?;
    run(&root, "cargo", &["check", "--workspace", "--all-targets"])?;
    run(
        &root,
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run(
        &root,
        "cargo",
        &["test", "--workspace", "--lib", "--bins", "--tests"],
    )?;
    run(&root, "cargo", &["test", "--doc", "--workspace"])?;
    // Feature-gated tests the workspace run does not reach.
    run(
        &root,
        "cargo",
        &[
            "test",
            "-p",
            "panweave-storage",
            "--features",
            "nor-flash,std",
        ],
    )?;
    // Run both feature-gated hub suites, including their interactions.
    // The workspace run covers capture requests returning NotSupported.
    run(
        &root,
        "cargo",
        &[
            "test",
            "-p",
            "panweave-hub",
            "--features",
            "radio-capture,alerts",
        ],
    )?;
    // The fuzz package is excluded from the workspace. A stable type
    // check catches API drift locally; CI additionally runs the targets
    // under libFuzzer with nightly and sanitizer instrumentation.
    run(
        &root,
        "cargo",
        &[
            "fmt",
            "--manifest-path",
            "fuzz/Cargo.toml",
            "--all",
            "--check",
        ],
    )?;
    run(
        &root,
        "cargo",
        &["check", "--manifest-path", "fuzz/Cargo.toml", "--bins"],
    )?;
    // The small-tables profile changes the dimensions of every endpoint
    // type: it must at least build with every feature (CI tests it).
    run(
        &root,
        "cargo",
        &[
            "check",
            "-p",
            "panweave",
            "--all-targets",
            "--features",
            "small-tables,crypto-software,std,smart-energy,direct,dlk",
        ],
    )?;
    // no_std verification for the core crates: build the library targets
    // without default features on a bare-metal target when it is installed.
    let no_std_crates = [
        "panweave-types",
        "panweave-codec",
        "panweave-mac",
        "panweave-security",
        "panweave-nwk",
        "panweave-aps",
        "panweave-zdo",
        "panweave-zcl",
        "panweave-device-library",
        "panweave-bdb",
        "panweave-storage",
        "panweave-runtime",
        "panweave-green-power",
        "panweave-direct",
        "panweave-smart-energy",
        "panweave",
        "panweave-hub",
        "panweave-lite",
    ];
    let target = std::env::var("PANWEAVE_NO_STD_TARGET")
        .unwrap_or_else(|_| "thumbv7em-none-eabihf".to_string());
    let installed = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(&target))
        .unwrap_or(false);
    if installed {
        for c in no_std_crates {
            run(
                &root,
                "cargo",
                &[
                    "check",
                    "-p",
                    c,
                    "--no-default-features",
                    "--target",
                    &target,
                ],
            )?;
        }
        // The hub engine is firmware too: it must build bare-metal with
        // its default features (the protocol alone is checked above).
        run(
            &root,
            "cargo",
            &[
                "check",
                "-p",
                "panweave-storage",
                "--no-default-features",
                "--features",
                "nor-flash",
                "--target",
                &target,
            ],
        )?;
        run(
            &root,
            "cargo",
            &["check", "-p", "panweave-hub", "--target", &target],
        )?;
        run(
            &root,
            "cargo",
            &[
                "check",
                "-p",
                "panweave-hub",
                "--features",
                "alerts",
                "--target",
                &target,
            ],
        )?;
    } else if require_no_std {
        return Err(format!(
            "required bare-metal target {target} is not installed"
        ));
    } else {
        println!("gate: target {target} not installed; skipping bare-metal no_std check");
    }
    lite_footprint(&root)?;
    conformance(true)?;
    codegen(true)
}

fn probe_target_dir(probe: &Path, override_dir: Option<&OsStr>) -> PathBuf {
    let directory = override_dir.map_or_else(|| Path::new("target"), Path::new);
    if directory.is_absolute() {
        directory.to_path_buf()
    } else {
        // Cargo resolves CARGO_TARGET_DIR relative to its working directory.
        probe.join(directory)
    }
}

/// Panweave Lite on the EFR32MG22: the link build of `examples/lite-probe`
/// (which fails when the static RAM leaves less than the stack reserve in
/// 32 KiB) and the footprint regression check against
/// `examples/lite-probe/footprint-baseline.json`; with QEMU installed the
/// measured-stack run too.
fn lite_footprint(root: &Path) -> Result<(), String> {
    let target = "thumbv8m.main-none-eabihf";
    let installed = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(target))
        .unwrap_or(false);
    if !installed {
        println!("gate: target {target} not installed; skipping the Lite footprint check");
        return Ok(());
    }
    let probe = root.join("examples").join("lite-probe");
    let target_dir = probe_target_dir(&probe, std::env::var_os("CARGO_TARGET_DIR").as_deref());
    let elf_dir = target_dir.join(target).join("release");
    run(
        &probe,
        "cargo",
        &["build", "--release", "--features", "dlk"],
    )?;
    let link = target_dir.join("efr32-dlk.elf");
    fs::copy(elf_dir.join("panweave-lite-probe"), &link).map_err(|e| e.to_string())?;
    let mut args = vec![
        root.join("scripts")
            .join("lite_footprint.py")
            .display()
            .to_string(),
        link.display().to_string(),
        "--check".into(),
        probe.join("footprint-baseline.json").display().to_string(),
    ];
    let qemu = Command::new("qemu-system-arm")
        .arg("--version")
        .output()
        .is_ok();
    if qemu {
        run(
            &probe,
            "cargo",
            &["build", "--release", "--features", "qemu,dlk"],
        )?;
        let log = target_dir.join("qemu-dlk.log");
        let out = Command::new("qemu-system-arm")
            .args([
                "-M",
                "mps2-an505",
                "-cpu",
                "cortex-m33",
                "-nographic",
                "-semihosting-config",
                "enable=on,target=native",
                "-kernel",
            ])
            .arg(elf_dir.join("panweave-lite-probe"))
            .output()
            .map_err(|e| format!("qemu: {e}"))?;
        fs::write(&log, &out.stdout).map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!(
                "the Lite QEMU scenario failed (see {})",
                log.display()
            ));
        }
        args.push("--qemu".into());
        args.push(log.display().to_string());
    } else {
        println!("gate: qemu-system-arm not found; the Lite stack is not measured");
    }
    let python = if cfg!(windows) { "python" } else { "python3" };
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run(root, python, &refs)
}

#[derive(Debug, Deserialize)]
struct DeviceMetadata {
    #[serde(default)]
    device: Vec<DeviceEntry>,
}

#[derive(Debug, Deserialize)]
struct DeviceEntry {
    id: u16,
    name: String,
    class: String,
    section: String,
    #[serde(default)]
    servers: Vec<u16>,
    #[serde(default)]
    clients: Vec<u16>,
}

/// Renders the device-type table of `panweave-device-library` from its
/// metadata file. With `check`, fails when the checked-in file differs.
fn codegen(check: bool) -> Result<(), String> {
    let root = workspace_root();
    let meta_path = root.join("panweave-device-library/metadata/devices.toml");
    let out_path = root.join("panweave-device-library/src/generated.rs");
    let text =
        fs::read_to_string(&meta_path).map_err(|e| format!("{}: {e}", meta_path.display()))?;
    let meta: DeviceMetadata =
        toml::from_str(&text).map_err(|e| format!("{}: {e}", meta_path.display()))?;
    let mut devices = meta.device;
    devices.sort_by_key(|d| d.id);
    let mut out = String::new();
    out.push_str(
        "//! Generated by `cargo xtask codegen` from
",
    );
    out.push_str(
        "//! `panweave-device-library/metadata/devices.toml` — do not edit.
",
    );
    out.push_str(
        "//!
//! Device types of the Device Type Library (document 23-02016-002)
",
    );
    out.push_str(
        "//! with their mandatory server and client clusters.

",
    );
    out.push_str(
        "use panweave_types::{ClusterId, DeviceId};

",
    );
    out.push_str(
        "use crate::{DeviceClass, DeviceType};

",
    );
    out.push_str(
        "/// Every device type of the library, sorted by identifier.
",
    );
    out.push_str(&format!(
        "pub const DEVICES: [DeviceType; {}] = [
",
        devices.len()
    ));
    for d in &devices {
        let class = match d.class.as_str() {
            "Simple" => "DeviceClass::Simple",
            "Dynamic" => "DeviceClass::Dynamic",
            "Node" => "DeviceClass::Node",
            other => return Err(format!("device 0x{:04X}: unknown class {other}", d.id)),
        };
        let list = |ids: &[u16]| -> String {
            ids.iter()
                .map(|c| format!("ClusterId(0x{c:04X})"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        out.push_str(
            "    DeviceType {
",
        );
        out.push_str(&format!(
            "        id: DeviceId(0x{:04X}),
",
            d.id
        ));
        out.push_str(&format!(
            "        name: {:?},
",
            d.name
        ));
        out.push_str(&format!(
            "        class: {class},
"
        ));
        out.push_str(&format!(
            "        section: {:?},
",
            d.section
        ));
        out.push_str(&format!(
            "        servers: &[{}],
",
            list(&d.servers)
        ));
        out.push_str(&format!(
            "        clients: &[{}],
",
            list(&d.clients)
        ));
        out.push_str(
            "    },
",
        );
    }
    out.push_str(
        "];
",
    );
    let current = fs::read_to_string(&out_path).unwrap_or_default();
    if check {
        if current != out {
            return Err(format!(
                "{} is out of date; run `cargo xtask codegen`",
                out_path.display()
            ));
        }
        println!("codegen: up to date ({} devices)", devices.len());
        return Ok(());
    }
    fs::write(&out_path, out).map_err(|e| format!("{}: {e}", out_path.display()))?;
    println!(
        "codegen: wrote {} ({} devices)",
        out_path.display(),
        devices.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "panweave-xtask-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn write(&self, relative: &str, source: &str) {
            let path = self.0.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, source).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn conformance_sources_are_scoped_to_declared_workspace_members() {
        let fixture = Fixture::new();
        fixture.write("Cargo.toml", "[workspace]\nmembers = [\"member\"]\n");
        fixture.write(
            "member/Cargo.toml",
            "[package]\nname = \"actual-package\"\n",
        );
        fixture.write("member/src/lib.rs", "#[test]\nfn real_test() {}\n");
        fixture.write(
            "member/tests/integration.rs",
            "#[tokio::test]\nasync fn async_test() {}\n",
        );
        let ignored = "#[test]\nfn ignored_test() {}\n";
        fixture.write("excluded/src/lib.rs", ignored);
        fixture.write("member/src/.private/private.rs", ignored);
        fixture.write("member/src/vendor/dependency.rs", ignored);
        fixture.write("member/src/target/generated.rs", ignored);
        let names = collect_test_names(&fixture.0).unwrap();
        assert_eq!(
            names,
            [
                "actual-package::async_test",
                "actual-package::real_test",
                "async_test",
                "real_test",
            ]
        );
    }

    #[test]
    fn proptest_helpers_do_not_count_as_test_functions() {
        let mut names = Vec::new();
        source_names(
            "fn helper() {}\nproptest! {\n#[test]\nfn property(value in any::<u8>()) {}\n}\nfn other_helper() {}\n",
            "package",
            &mut names,
        );
        assert_eq!(names, ["package::property", "property"]);
    }

    #[test]
    fn probe_artifacts_use_the_probes_default_or_relative_target_directory() {
        let probe = workspace_root().join("examples").join("lite-probe");
        assert_eq!(probe_target_dir(&probe, None), probe.join("target"));
        assert_eq!(
            probe_target_dir(&probe, Some(OsStr::new("../shared-build"))),
            probe.join("../shared-build")
        );
    }

    #[test]
    fn an_absolute_external_target_directory_is_not_rebased_under_the_probe() {
        let probe = workspace_root().join("examples").join("lite-probe");
        let external = std::env::temp_dir().join("panweave-probe-output");
        assert!(external.is_absolute());
        assert_eq!(
            probe_target_dir(&probe, Some(external.as_os_str())),
            external
        );
    }
}
