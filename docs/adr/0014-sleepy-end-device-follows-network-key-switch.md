# ADR-0014: A sleepy end device follows its parent onto the alternate network key

* Status: accepted
* Date: 2026-09-17
* Specification: `R23.2 §4.6.3.4` (network key update), `§4.4.6.1.3`
  (Switch Key is broadcast to 0xFFFD), `§4.4.2.3` last paragraph
  (routers unicast the broadcast Transport Key to rx-off children),
  `§4.3.1.2` (incoming frames name their key sequence number)

## Context

A Trust Center distributes a new network key as the alternate key and
then broadcasts a Switch Key command. §4.4.6.1.3 sends that broadcast to
the rx-on-when-idle address 0xFFFD, and §4.4.6.1.3 also forbids
unicasting it ("The switch key SHALL NOT be unicast", §4.6.3.4.1). A
sleepy end device therefore receives the new key (its parent unicasts
the Transport Key per §4.4.2.3) but never the command that makes it
active. The specification does not say how such a device learns of the
switch; it only requires (§4.3.1.2) that incoming frames be unsecured
with the key the auxiliary header names, which a device holding the
alternate key can do.

Deployed stacks resolve this by treating the first frame from the
parent secured under the alternate key as the switch: from then on the
parent uses the new key for everything, so the child must too, or its
own transmissions (still under the old key) will be dropped once the
parent retires that key at the next update.

## Decision

`panweave-nwk` switches the active network key of a sleepy end device
(`nwkRxOnWhenIdle` false) when a frame from its parent is successfully
unsecured under a stored key other than the active one. Routers,
coordinators and rx-on end devices switch only on the Switch Key
command, as §4.6.3.4.2 says; they keep accepting frames under either
stored key regardless. The retired key stays in its slot until the next
update replaces it, on every device type.

The Trust Center runtime (`Stack::update_network_key`) broadcasts the
Transport Key, waits `nwkNetworkBroadcastDeliveryTime`, then broadcasts
the Switch Key and switches itself; it and every router unicast the
Transport Key to their rx-off children (§4.4.2.3), the frame being held
by the MAC until the child polls.

## Consequences

* A sleepy end device that sleeps through the whole update and wakes
  after the next one (two rotations) has neither key and must rejoin,
  as it would with any other stack.
* The implicit switch happens only for frames from the parent, so a
  spoofed frame from elsewhere under a known alternate key cannot move
  the device; a frame under an unknown sequence number is dropped as
  before (`SecurityError::NoKey`).
* Conformance row `PW-R23-SEC-020` records the interpretation.
