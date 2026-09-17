# ADR-0003: NLME-JOIN.confirm precedes authorization

* Status: accepted
* Date: 2026-09-17
* Specification: `R23.2 §3.2.2.13` (NLME-JOIN.confirm), `§4.6.3.2.3`
  (joining device operation), `§4.6.3.2.3.2` (joining complete)

## Context

After a successful MAC association or Network Commissioning response the
device is "joined but unauthorized". The NWK layer issues NLME-JOIN.confirm
with SUCCESS at that point; authorization only completes when the APS
delivers the network key. If the key never arrives the device must leave
(`§4.6.3.2.3.2`).

## Options considered

1. Delay NLME-JOIN.confirm until the network key is installed.
2. Confirm the join immediately and report a separate authentication
   timeout when `apsSecurityTimeOutPeriod` elapses without a key.

## Decision

Option 2, matching the primitive semantics in `§3.2.2.13`. `Nwk` emits
`NwkEvent::JoinConfirm { status: Success, secured: false }` and starts the
security timer on the parent's neighbour entry;
`NwkEvent::AuthenticationTimeout` follows if no network key is installed
in time, after which the runtime performs the NWK leave. `Aps` mirrors
this with `DeviceState::JoinedUnauthorized` → `JoinedAuthorized` on the
Transport Key.

## Consequences

* The runtime (and BDB commissioning state machine) must treat a join as
  complete only after `ApsEvent::TransportKey { authorizes: true }`.
* Tests: `coordinator_forms_and_end_device_joins_and_exchanges_data`
  (panweave-nwk), `trust_center_join_and_link_key_update` (panweave-aps).
