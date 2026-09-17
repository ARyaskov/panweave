# ADR-0012: CBKE curve arithmetic is supplied by the host; Table 5-12 gaps

* Status: accepted
* Date: 2026-09-17
* Specification: `SE 1.4a Annex C.4.2` (Cryptographic Suite 1 / 2 building
  blocks), `C.4.2.4` (Certificate-Based Key-Establishment), `C.5` / `C.6`
  (test vectors), `§5.4.6` Table 5-12

## Context

The Key Establishment cluster's two cryptographic suites run the Elliptic
Curve MQV scheme (SEC1 §6.2) with SEC4 implicit certificates over the
binary Koblitz curves sect163k1 and sect283k1. There is no RustCrypto
implementation of these curves, and the project's security posture
(constant-time code from vetted primitives, no hand-rolled cryptography)
rules out writing binary-field arithmetic and ECMQV in this workspace.
Annex C.5.3.1 itself assumes "an ECC library … separately validated with a
set of ECC test vectors" and puts those vectors outside the specification.

Separately, the pdftotext rendering of Table 5-12 (Security Key
Assignments per Cluster) is unreadable for the rows Power Configuration,
Key Establishment and Keep-Alive: the Link Key Required column is
vertically displaced and the three cells are blank in every extraction
mode tried.

## Decision

* `panweave-smart-energy::key_establishment` implements everything around
  the primitive: the cluster codecs, certificate formats and checks, the
  KDF (`H(Z || 00000001)`, `H(Z || 00000002)`), the MACU / MACV
  confirmation transforms and the initiator / responder machines with
  the Terminate semantics of C.3.1.2.3. The curve arithmetic is reached
  through the `Ecmqv` trait (ephemeral key generation and shared-secret
  computation for one suite); the host supplies a validated
  implementation. The transforms are verified against the C.5 and C.6
  vectors from the published shared secret `Z` onward, which is exactly
  the boundary the specification itself draws for its vectors.
* `link_key_required` treats Key Establishment as exempt from APS link-key
  security: its exchange is what creates the key, and the Annex C.5.2 /
  C.6.2 frames carry APS frame control 0x40 (no security). Power
  Configuration and Keep-Alive are treated as exempt as well, like the
  other network-key-only general clusters (Basic, Identify, Time); the
  Keep-Alive client in `panweave-runtime` nevertheless secures its reads
  with the Trust Center link key as R23.2 requires, which Table 5-12
  permits ("It is permissible for a device to initiate a ZCL exchange
  using an application link key even when not required").

## Consequences

* PW-SE-SEC-004 stays `partially-implemented` until a host-supplied
  `Ecmqv` has been exercised end to end; PW-SE-SEC-003 is
  `requires-clarification` for the three unreadable rows.
* A conformance run against a real ESI needs the host's ECMQV
  implementation; the workspace tests substitute a vector-replaying
  primitive.
