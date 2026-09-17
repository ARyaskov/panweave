# ADR-0002: Which unsecured NWK frames a secured network accepts

* Status: accepted
* Date: 2026-09-17
* Specification: `R23.2 §3.6.1.4.3` / `§4.3.1.2` (incoming frame security),
  `§4.6.3.2.1` (router operation during joining), `§4.6.3.7` (tunnelling
  and relaying)

## Context

On a secured network every NWK data frame is normally protected with the
network key. During joining, however, the parent must forward Transport
Key, Tunnel-extracted and Relay Message Downstream frames to a child that
has no network key yet, and the child sends Relay Message Upstream frames
to its parent without NWK security. The specification states that these
frames are sent "with security disabled" but does not enumerate, at the
NWK layer, which unsecured frames a device SHALL accept.

## Options considered

1. Accept any unsecured NWK data frame and let the APS filter.
2. Accept unsecured NWK data frames only while joined-but-unauthorized
   and only from the parent.
3. Accept unsecured NWK data frames whose payload is an APS command frame
   (frame type 01) or an APS-secured frame from a neighbour, and hand
   everything else to security processing.

## Decision

Option 3 at the NWK layer, combined with the APS acceptance policy of
`§4.4.1.3` (Tables 4-6/4-7) at the APS layer. The NWK layer cannot judge
the APS security of the payload, but the APS frame control is in the
clear and all legitimate unsecured joining traffic consists of APS command
frames (Transport Key, Relay Message, Tunnel-extracted commands) or
APS-secured frames that the parent extracted from a Tunnel/Relay command.
The APS then requires link-key protection for anything it acts on while
unauthorized (`Aps::handle_data`, `Aps::command_allowed`). Frames that
pass the NWK filter but fail APS policy are counted in
`ApsStats::policy_dropped`.

## Consequences

* `panweave-nwk::layer::rx::unsecured_frame_allowed` implements the filter.
* `panweave-aps` tests `unauthorized_joiner_ignores_data_and_unencrypted_key`
  and `relayed_frames_reach_the_trust_center_and_back` cover the APS side.
