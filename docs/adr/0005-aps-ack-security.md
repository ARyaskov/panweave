# ADR-0005: APS acknowledgements mirror the security of the acknowledged frame

* Status: accepted
* Date: 2026-09-17
* Specification: `R23.2 §2.2.5.2.3` (acknowledgement frame format),
  `§2.2.8.4.3.2` (acknowledgement), `§4.4.1` (APS frame security)

## Context

The specification fixes the header fields of an APS acknowledgement but
does not state whether an acknowledgement of an APS-encrypted frame is
itself APS-encrypted. Widely deployed stacks encrypt such acknowledgements
with the same link key; an unencrypted acknowledgement lets a third party
forge delivery confirmations for link-key-protected traffic.

## Options considered

1. Never APS-secure acknowledgements.
2. Always APS-secure acknowledgements when a link key exists.
3. Secure the acknowledgement exactly as the acknowledged frame was
   secured (same link key, data key identifier), NWK security as received.

## Decision

Option 3 (`Aps::send_ack`). It preserves the sender's security
expectation, matches deployed behaviour and costs one frame counter per
acknowledged secured frame. When the link-key counter has no persisted
reservation yet the acknowledgement is skipped once and the reservation
requested; the sender's retransmission is acknowledged after the commit.

## Consequences

* Tests: `link_key_secured_data_round_trip`,
  `acked_unicast_is_delivered_once_and_confirmed`.
* Received acknowledgements are matched regardless of their security so
  that peers following option 1 still complete transmissions.
