# ADR-0006: The APS counter starts at a random value after every reset

* Status: accepted
* Date: 2026-09-17
* Specification: `R23.2 §2.2.5.1.7` (APS counter), `§2.2.8.4.2`
  (duplicate rejection), `§3.6.9` (persistent data)

## Context

The APS counter is an 8-bit field that "SHALL be incremented by one for
each new transmission"; the specification neither fixes its initial value
nor lists it among the persistent data. Receivers keep a duplicate
rejection table keyed by source address and APS counter with "timing
information" (Panweave uses `apscAckWaitDuration × (1 + apscMaxFrameRetries)`
= 6.4 s, `panweave_aps::aib::constants::DUPLICATE_REJECTION_TIMEOUT`).

A device that reboots and restarts its counter at zero within that window
has its first frames silently discarded by every peer that still holds an
entry for the same counter value — observed in the warm-start test as a
lost Default Response after an end-device reboot.

## Options considered

1. Start at zero (simplest; the observed failure).
2. Persist the counter like the security frame counters (a flash write per
   APS frame, or a reservation scheme for an 8-bit value that wraps every
   256 frames — no real protection either way).
3. Seed the counter from the RNG on every boot, as `nwkSequenceNumber` is
   (its NIB default is "Random", R23.2 Table 3-63).
4. Flush a peer's duplicate entries when it rejoins (not specified;
   rejoins are not the only cause of a restart).

## Decision

Option 3. `Aps::seed_counter` is called by the runtime with an RNG octet
at construction. The residual collision probability per stale entry is
1/256, the same exposure the specification accepts for any wrap-around of
the 8-bit counter.

## Consequences

* No change to the wire format or to duplicate rejection.
* Test determinism is preserved because the test RNG is seeded.
* The ZCL transaction sequence number is left at zero: ZCL responses are
  matched to outstanding requests by the initiator, not deduplicated by
  the responder.
