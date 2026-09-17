# Changelog

All notable changes to Panweave are documented here. The format follows
Keep a Changelog; versions follow SemVer.

## [Unreleased]

### Added

* Workspace scaffold, specification map, architecture, security and storage
  models, conformance database.
* `panweave-types`, `panweave-codec`: core identifiers, zero-copy reader /
  writer, Annex I TLV processing.
* `panweave-mac`: 802.15.4 frame codec and the MAC service subset of
  R23.2 Annex D (software acknowledgements, indirect queue, association,
  scanning, polling).
* `panweave-security`: CCM*, AES-MMO, key hierarchy, frame counters with
  persisted reservations, network / link key material, Trust Center
  policies, Curve25519 SPEKE key negotiation primitives.
* `panweave-nwk`: NWK frames and commands, routing, broadcasting,
  discovery / formation / joining (association, rejoin, Network
  Commissioning), end-device aging, PAN ID and address conflicts.
* `panweave-aps`: APS frames, commands, link-key security, acknowledged
  transmission, fragmentation (window 1), binding / group / duplicate
  rejection tables and the Transport / Update / Remove / Request / Switch /
  Verify / Confirm Key, Tunnel and Relay services.
* `panweave-zdo`: descriptors, ZDP codecs and server / client processing.
* `panweave-zcl`: data types, frames, global commands, attribute store,
  reporting and endpoint dispatch; Basic, Identify and On/Off.
* `panweave-storage`, `panweave-testkit`, `panweave-runtime`: storage
  abstraction, virtual clock / medium / test RNG and the sans-I/O stack
  driver; the Milestone 1 end-to-end test.
