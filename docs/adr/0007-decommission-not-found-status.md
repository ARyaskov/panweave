# ADR-0007: Security_Decommission_rsp reports NO_MATCH when nothing matched

* Status: accepted
* Date: 2026-09-17
* Specification: `R23.2 §2.4.3.4.7.4` step 11, `§2.4.4.4.7` (Table 2-125),
  `§2.4.5` (Table 2-129)

## Context

The processing rules of Security_Decommission_req end with "the Status
SHALL be set to NOT_FOUND" when no EUI-64 in the request matched a
key-pair or binding entry. `NOT_FOUND` is not among the ZDP enumerations
of Table 2-129, and Table 2-125 lists only SUCCESS, INV_REQUESTTYPE,
NOT_AUTHORIZED and NOT_SUPPORTED for this response.

## Options considered

1. Emit an unspecified octet for "NOT_FOUND".
2. Report SUCCESS regardless.
3. Report `NO_MATCH` (0x86), defined as the failure to match the request
   against local tables.

## Decision

Option 3. `NO_MATCH` is a defined enumeration with the intended meaning
and cannot be confused with a successful decommissioning. Receivers of
the response treat any non-SUCCESS status as "no change".

## Consequences

* Implementations that expect a literal "NOT_FOUND" octet will see 0x86.
* Revisit when a corrigendum defines the value.
