# ADR-0017: Admitting Zigbee Direct Virtual Devices through a Trusted Link

* Status: accepted
* Date: 2026-09-18
* Specification: `R23.2 §3.2.2.41–§3.2.2.44`, `§4.6.3.2.2.4`, `Table 4-9`;
  `Zigbee Direct 1.1 §6.3.2.1`, `§7.7.3.6`, `§7.7.4`, `§9`

## Context

A Zigbee Virtual Device (ZVD) reaches the network through a ZDD's Tunnel
Service: its NWK frames travel as NPDU Message TLVs over a BLE session
instead of the radio, and the network key must never reach it. The
specifications leave a few points to the implementation.

1. **Where the Trusted Link lives.** R23.2 defines the
   NLME-TRUSTEDLINK primitives and a `nwkMacInterfaceTable` entry type,
   the Direct specification the TLV and the security flag; neither says
   how a peer behind the link is represented in the NWK layer.
2. **The Basic Authorization Key descriptor.** R23.2 Table 4-9 assigns
   StandardKeyType 0xB2 and refers to the Direct specification, which
   says the "Key Descriptor field [is] set to the basic authorization
   key" and that the ZVD "is also provided with the key sequence number
   of the Zigbee NWK key used to derive" it, without a figure.
3. **What "assume security" means on transmission.** The
   POSTPROCESSING request's `assumeSecurity` parameter is the NWK's to
   set.
4. **Remembering virtual devices.** §4.6.3.2.2.4 records
   `isVirtualDevice` in the key-pair descriptor so that a network key
   rotation delivers a Basic key rather than the new network key.

## Decision

1. A peer behind a Trusted Link is an ordinary neighbour table entry
   with a `link` index (`NeighborEntry::link`, volatile). A frame
   received over the link is processed by the same NWK path as a radio
   frame with the header's source as MAC source, the link's peer as the
   securing device when `assumeSecurity` is set, and no auxiliary header
   (a frame with the security bit set is malformed). A joiner heard over
   the link is created behind it. Unicasts whose next hop is such a
   neighbour, and one copy per link of every broadcast this device
   originates or relays, leave as `NwkAction::TrustedLinkData` carrying
   the plaintext with the security bit cleared.
2. The 0xB2 descriptor uses the Network Key Descriptor layout (key,
   sequence number, destination, source): it carries exactly the fields
   the Direct specification asks for, and a ZVD parsing it can reuse its
   network-key descriptor code. This is an interpretation
   (`requires-clarification` in the conformance notes).
3. `assumeSecurity` is set when the frame would have been NWK-secured on
   the radio (the `secure` flag of the transmission): the link's
   encryption stands in for NWK security exactly where it would apply.
4. Virtual devices are kept in a runtime list (`Stack::virtual_devices`,
   with the parent they joined through) rather than in the persisted
   key-pair set, so the key-pair storage format is unchanged; the list
   is lost on restart and a ZVD then needs a Trust Center rejoin, which
   the Limited Authorization session of ZD §9.1 provides for.
5. The ZDD applies the §7.7.4.8 and §9 filters at the facade: a Network
   Commissioning Request over the tunnel without the Device Capability
   Extension ZVD flag is dropped before the stack sees it, and a data
   frame the APSME's `forwarding_decision` declines (a Transport Key
   conveying a network key, or a key-transport-key secured command) is
   reported as `Event::DirectTunnelDeclined` for the host to close the
   connection instead of being tunnelled.

## Consequences

* The Trust Center transports the Basic key APS-secured with the
  key-load derivative of the ZVD's Trust Center link key (the well-known
  key when no install code was given) and, on every network key update,
  a Basic key derived from the prospective key; it never tunnels the
  network key itself.
* Regular network traffic (link status, route requests) the ZDD emits is
  not copied to the link: only frames addressed to the ZVD or broadcasts.
* A ZVD-side stack is not provided: a host receiving
  `StackEvent::BasicAuthorizationKey` feeds its BLE session layer.
