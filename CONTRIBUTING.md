# Contributing

Thank you for helping build Panweave.

## Ground rules

* Protocol behaviour must be traceable to a specification section. Add the
  reference in a comment (`Spec: R23.2 §3.6.4.5`) and update
  `conformance/*.toml`.
* Do not paste specification prose, tables or figures. Paraphrase.
* Every parser must be panic-free for arbitrary input and must have a fuzz
  target or be reachable from one.
* No `unsafe` without a documented safety invariant and a test.
* Secret-bearing types must redact `Debug`.
* Tests use virtual time (`panweave-testkit::VirtualClock`); never sleep.

## Workflow

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo xtask gate
```

Commits: `feat(nwk): ...`, `fix(aps): ...`, `test(sim): ...`, `docs: ...`.

## Decisions

Non-obvious interpretations of the specification are recorded in
`docs/adr/NNNN-title.md` using the template in `docs/adr/0000-template.md`.
