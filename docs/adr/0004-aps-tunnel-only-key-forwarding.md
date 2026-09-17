# ADR-0004: Network keys reach joiners through Tunnel, not parent forwarding

* Status: accepted
* Date: 2026-09-17
* Specification: `R23.2 §4.4.2.1.3` (APSME-TRANSPORT-KEY.request,
  UseParent / TunnelCommand), `§4.4.2.3` (receipt of Transport Key),
  `§4.6.3.7` (command tunnelling)

## Context

`§4.4.2.1.3` allows a Trust Center to send a network key to a joiner's
parent (`UseParent = TRUE`) without wrapping it in a Tunnel command, and
`§4.4.2.3` asks the parent to forward a Transport Key whose destination
address field is not its own. The command is, however, APS-encrypted with
the joiner's link key, which the parent does not hold, and `§4.4.2.3`
requires security processing to run before the key type and destination
are examined. The parent therefore cannot recognise such a frame as one to
forward. The Tunnel command (`§4.4.11.6`, `§4.6.3.7`) exists precisely to
carry the destination in the clear.

## Options considered

1. Implement UseParent-without-Tunnel by forwarding any Transport Key
   that fails APS security processing at a parent with unauthenticated
   children.
2. Support only the Tunnel command (and Relay Message Downstream) for
   delivering keys to non-neighbour joiners.

## Decision

Option 2. Forwarding undecryptable frames on speculation would let any
device use a parent as a reflector towards its unauthenticated children,
and interoperating stacks use the Tunnel command. `Aps::transport_network_key`
offers `KeyRoute::Direct` (neighbour joiner), `KeyRoute::Tunnel` and
`KeyRoute::Broadcast`. A received Transport Key whose destination is
neither this device nor all zeros is dropped and counted as a policy drop.

## Consequences

* Conformance `PW-R23-SEC-018` notes the limitation.
* Should a peer rely on the untunnelled form, interoperability testing on
  hardware will show it as a join failure with `policy_dropped`
  incrementing.
