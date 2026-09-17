# ADR-0010: PAN ID conflicts are counted, never resolved automatically

* Status: accepted
* Date: 2026-09-17
* Specification: `R23.2 §2.3.4`, `§3.6.1.13`, `§2.4.3.3.9.2`

## Context

Revisions before 23 made a device report a PAN ID conflict as soon as it
saw a beacon with its own PAN ID and a foreign extended PAN ID, and made
the network manager pick and broadcast a new PAN ID on the spot. Revision
23 (§2.3.4.2, §3.6.1.13.1) forbids the unsolicited Network Report, keeps
only `nwkPanIdConflictCount`, and lets a network manager that still
receives legacy reports surface them as NLME-NETWORK-STATUS 0x14. The
specification leaves the decision to change the PAN ID to "other
metrics from the higher layer" and warns that a malicious device can
fabricate conflicts.

## Decision

* Detection only increments `nwkPanIdConflictCount` (saturating). The
  count is readable through `Stack::pan_id_conflicts()` and served, then
  reset, by Security_Get_Configuration_rsp (PAN ID Conflict Report TLV).
* A legacy Network Report received by the network manager is turned into
  `StackEvent::PanIdConflictReport { from }`; nothing else happens.
* The PAN ID changes only when the application calls
  `Stack::change_pan_id()` (§3.6.1.13.3): a staged `nwkNextPanId` is used
  when present, otherwise a random unused one; the Network Update is
  broadcast, the manager and every receiver switch after
  `nwkNetworkBroadcastDeliveryTime`, and receivers drop an update whose
  PAN ID differs from a staged `nwkNextPanId` (§3.6.1.13.4).
* No "vendor specific configurable mechanism" for automatic resolution
  is offered: the stack never resolves a conflict on its own.

## Consequences

* An application that wants R21-style behaviour has to implement the
  policy itself (poll `pan_id_conflicts()` on routers with
  Security_Get_Configuration_req, weigh connectivity, then call
  `change_pan_id()`).
* Sleepy end devices miss the broadcast; they rejoin through the usual
  parent-loss procedure. Applications should stage the change with
  Security_Set_Configuration_req to those devices first.
