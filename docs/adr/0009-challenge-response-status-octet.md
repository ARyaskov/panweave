# ADR-0009: Security_Challenge_rsp carries a status octet

* Status: accepted
* Date: 2026-09-17
* Specification: `R23.2 §2.4.4.4.8` (Figure 2-90), `§2.4.3.4.8.4`,
  `§4.6.3.8.4`

## Context

Figure 2-90 shows the Security_Challenge_rsp frame as "TLVs" only, while
the receipt rules of the request (§2.4.3.4.8.4 steps 2 and 4) generate
the response "with a status of MISSING_TLV" / "NO_MATCH" and the
responder procedure (§4.6.3.8.4 step 2a) sets "the Status to SUCCESS".
Every other ZDP response starts with a status octet.

## Decision

The response is encoded as `Status || TLVs`, like the other security
service responses. A receiver only acts on SUCCESS responses that carry
the APS Frame Counter Response TLV matching its outstanding challenge.

## Consequences

* Interoperability with an implementation following the figure literally
  would fail on the first octet; a corrigendum resolving the figure will
  be adopted when published.
