# ADR-0001: Use the MAC LQI as the NWK link quality assessment (LQA)

* Status: accepted
* Date: 2026-09-17
* Specification: `R23.2 §3.6.3.1` (link cost, Table 3-76), `§3.6.1.5.2`
  (parent ranking), Annex D (MAC subset)

## Context

R23.2 defines link costs and neighbour ranking in terms of an LQA value
that an implementation derives from the radio's link quality indication,
but it does not specify the mapping from the 802.15.4 LQI (0–255) to the
LQA used by Table 3-76 and `nwkGoodParentLqa`. Radios differ in how they
compute LQI (RSSI-based, correlation-based, or a blend).

## Options considered

1. Treat the radio LQI as the LQA directly.
2. Define a Panweave-specific mapping from RSSI/LQI to LQA.
3. Require the radio HAL to supply an LQA in addition to LQI.

## Decision

Option 1. The MAC layer forwards the LQI supplied by the radio and the
NWK layer feeds it through the median-of-three filter (`LqaFilter`) before
mapping it with Table 3-76. A radio HAL that has a better estimate maps it
onto the 0–255 LQI range itself (`docs/radio-hal.md`). This keeps the core
free of radio-specific calibration while still allowing a port to improve
the assessment.

## Consequences

* `panweave-nwk::neighbor::link_cost_from_lqa` documents the assumption.
* Conformance entries for link cost and parent selection are marked
  `requires-hardware-validation` where the outcome depends on radio
  behaviour.
