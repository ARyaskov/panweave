# Security policy

## Reporting

Please report suspected vulnerabilities privately by e-mail to the
maintainers listed in `Cargo.toml` (`authors`) with the subject
`[panweave-security]`. Do not open public issues for undisclosed
vulnerabilities. You should receive an acknowledgement within 7 days.

## Scope

In scope: any behaviour of the Panweave crates that allows an attacker with
radio (or BLE, for Zigbee Direct) access to

* crash, hang, or exhaust memory of a Panweave node with crafted frames;
* bypass Trust Center policy, key attribute checks, or frame-counter
  replay protection;
* recover key material from logs, debug output, or storage records that
  are documented as non-secret;
* cause nonce reuse or frame-counter rollback.

Out of scope: weaknesses inherent to the specifications themselves (for
example, use of the well-known global link key where the specification
permits it), and issues in vendor radio drivers outside this repository.

## Model

See `docs/security-model.md` for trust boundaries, assets and mitigations.
