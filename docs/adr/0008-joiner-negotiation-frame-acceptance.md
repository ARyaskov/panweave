# ADR-0008: Which unsecured frames a joining device accepts during key negotiation

* Status: accepted
* Date: 2026-09-17
* Specification: `R23.2 §4.6.3.2.2.2`, `§4.6.3.2.3.1`, `§4.6.3.5`,
  `§4.4.11.7` (Relay Message), `§3.6.4.4` (NWK security processing)

## Context

Dynamic Link Key Negotiation Joining runs before the joiner holds the
network key: the Trust Center's Security_Start_Key_Update_req and
Security_Start_Key_Negotiation_rsp are relayed by the parent inside
Relay Message Downstream, and the parent hands the extracted APS frame
to its unauthenticated child NWK-unsecured and APS-unsecured. The joiner
therefore has to accept some unsecured data frames, which the general
rule of §3.6.4.4 / §4.4.1.2 forbids, and §4.6.3.2.3.1 restricts what it
may process to the key negotiation messages.

When the Trust Center is itself the parent there is no relay at all: the
frames travel directly, NWK-unsecured, between the two devices.

## Decision

* NWK layer: a joined-but-unauthenticated device accepts NWK-unsecured
  data frames only from its parent (`nwkParentAddress`); the APS layer
  decides further.
* APS layer: while `JoinedUnauthorized`, unsecured ZDP frames are limited
  to Security_Start_Key_Update_req (0x0045),
  Security_Start_Key_Negotiation_rsp (0x8040) and
  Security_Retrieve_Authentication_Token_rsp (0x8041); everything else
  unsecured is dropped. They are attributed to the Trust Center address
  and marked as relayed so that responses go back through the parent.
  An APS-secured Confirm Key is accepted in this state.
* Trust Center: relayed, unsecured Security_Start_Key_Negotiation_req
  (0x0040) and Security_Start_Key_Update_rsp (0x8045) are accepted from
  its unauthenticated children's relays; a relayed Verify Key is
  accepted and confirmed through the same relay.
* When the Trust Center is the parent, "relayed" destinations whose
  relaying hop is the joiner itself are delivered directly and
  NWK-unsecured (Confirm Key, ZDO frames, the network key).
* A joined-but-unauthenticated device includes its IEEE address in the
  NWK header of the frames it originates so that the parent can match
  them to its unauthenticated child.

## Consequences

* A rogue neighbour can only inject the three whitelisted ZDP frames at
  a joiner, all of which are authenticated by the SPEKE exchange or
  ignored without a matching request.
* The Trust Center's authentication token response is delivered APS
  encrypted with the negotiated key in every case.
