//! Repository automation for Panweave.
//!
//! Sub-commands:
//!
//! * `conformance [--check]` — render `docs/conformance.md` from
//!   `conformance/*.toml` and verify that every referenced test exists.
//! * `codegen [--check]` — render `panweave-device-library/src/generated.rs`
//!   from `panweave-device-library/metadata/devices.toml`.
//! * `gate` — run the full quality gate (fmt, check, clippy, tests, no_std
//!   builds, conformance and codegen checks).

use std::collections::BTreeMap;
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
        Some("gate") => gate(),
        _ => {
            eprintln!("usage: cargo xtask <conformance [--check] | codegen [--check] | gate>");
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

/// Collects `fn <name>()` test names from every Rust source under the
/// workspace so that `tests = [...]` references can be validated.
fn collect_test_names(root: &Path) -> Vec<String> {
    let mut names = Vec::new();
    fn walk(dir: &Path, names: &mut Vec<String>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for entry in rd.filter_map(Result::ok) {
            let path = entry.path();
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            if path.is_dir() {
                if file_name == "target" || file_name == ".git" {
                    continue;
                }
                walk(&path, names);
            } else if path.extension().is_some_and(|x| x == "rs") {
                let Ok(text) = fs::read_to_string(&path) else {
                    continue;
                };
                let crate_name = path
                    .components()
                    .filter_map(|c| c.as_os_str().to_str())
                    .find(|c| c.starts_with("panweave"))
                    .unwrap_or("")
                    .to_string();
                let mut pending_test = false;
                for line in text.lines() {
                    let t = line.trim();
                    if t.starts_with("#[test]") || t.starts_with("#[tokio::test") {
                        pending_test = true;
                        continue;
                    }
                    if pending_test {
                        if let Some(rest) = t.strip_prefix("fn ") {
                            let name: String = rest
                                .chars()
                                .take_while(|c| c.is_alphanumeric() || *c == '_')
                                .collect();
                            names.push(format!("{crate_name}::{name}"));
                            names.push(name);
                            pending_test = false;
                        } else if t.starts_with("#[") || t.starts_with("async fn") {
                            if let Some(rest) = t.strip_prefix("async fn ") {
                                let name: String = rest
                                    .chars()
                                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                                    .collect();
                                names.push(format!("{crate_name}::{name}"));
                                names.push(name);
                                pending_test = false;
                            }
                        } else {
                            pending_test = false;
                        }
                    }
                    // proptest! blocks: `fn name(` inside macro
                    if text.contains("proptest!")
                        && let Some(rest) = t.strip_prefix("fn ")
                    {
                        let name: String = rest
                            .chars()
                            .take_while(|c| c.is_alphanumeric() || *c == '_')
                            .collect();
                        names.push(format!("{crate_name}::{name}"));
                        names.push(name);
                    }
                }
            }
        }
    }
    walk(root, &mut names);
    names.sort();
    names.dedup();
    names
}

fn conformance(check: bool) -> Result<(), String> {
    let root = workspace_root();
    let inventories = load_inventories(&root)?;
    let tests = collect_test_names(&root);
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

fn gate() -> Result<(), String> {
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
    run(&root, "cargo", &["test", "--workspace"])?;
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
    } else {
        println!("gate: target {target} not installed; skipping bare-metal no_std check");
    }
    conformance(true)?;
    codegen(true)
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
