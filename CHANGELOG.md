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
* Milestone 2: router + sleepy end device (polling, tunnelled key, routed
  reports, rejoin after router failure); network-wide permit joining.
* Persistence and warm start: NIB, network keys, end-device children,
  link keys / AIB, bindings and groups are stored through the `Storage`
  trait on layer triggers; `Stack::restore` / `Stack::resume` rebuild a
  device after a reset (routers resume, end devices rejoin securely) with
  frame counters continuing past the last persisted reservation;
  `Stack::erase_persisted` for factory reset. The APS counter is seeded
  from the RNG on boot (ADR-0006).
* `panweave-bdb`: BDB 3.1 commissioning state machine — network
  formation, off-/on-network steering with same-network retries and the
  secondary channel list, the rejoin procedure, finding & binding as
  target and initiator (unicast and group bindings) — driven through a
  `Node` trait implemented by the runtime `Stack`; `BdbApp` in the
  simulator and an end-to-end commissioning test.
* `panweave-zcl`: Identify server behaviour (countdown, Identify Query
  Response, Trigger Effect event) and the Groups cluster executed by the
  endpoint dispatcher against the APS group table.
* Dynamic Link Key negotiation (R23.2 §4.4.9): the ZDO security services
  (Security_Start_Key_Negotiation, Retrieve_Authentication_Token,
  Get_Authentication_Level, Set/Get_Configuration, Start_Key_Update,
  Decommission and their TLVs), the joiner and Trust Center state machines
  in the runtime with entry backup/restore and deadlines, relayed
  Verify / Confirm Key, the authentication token exchange, and the
  acceptance rules of ADR-0008. Enabled by the `dlk` feature; tested with
  anonymous and install-code joins through a router and with the Trust
  Center as parent.
* APS frame counter verification (R23.2 §4.6.3.8): `VerifiedFrameCounter`
  per key-pair entry (cleared on reboot), unverified frames dropped and
  synchronized through Security_Challenge_req/rsp with the CCM MIC-64
  challenge key / nonce derivation (`panweave-security::challenge`).
* Network management: Mgmt_NWK_Update_req processing (energy scans with
  Mgmt_NWK_Update_notify, channel change honouring nwkNextChannelChange
  and nwkUpdateId, channel mask / network manager update), the Trust
  Center's Beacon Appendix Encapsulation in Mgmt_Permit_Joining_req and
  the network-wide beacon appendix in router beacons, Remove Device
  through a parent with Device Left reports.
* R23 PAN ID conflict semantics (ADR-0010): conflicts only increment
  `nwkPanIdConflictCount`, legacy Network Reports surface as
  `StackEvent::PanIdConflictReport`, and the PAN ID changes only through
  `Stack::change_pan_id()`; receivers gate the Network Update by a staged
  `nwkNextPanId`.
* ZCL general clusters executed by the endpoint dispatcher: the full
  On/Off server (timed off, Off With Effect, global scene), Level Control
  with 100 ms transitions and the Table 3-55 On/Off coupling, Scenes with
  a 16-entry table per endpoint and the On/Off / Level extension field
  sets, Poll Control server and client wired to the sleepy end device's
  MAC poll rate, the Keep-Alive server plus the routers' Trust Center
  keep-alive client (`StackEvent::TrustCenterLost`), Basic Reset to
  Factory Defaults, BDB §6.5 default reporting configurations, and
  APS-secured replies to APS-secured requests. `ZclEvent` / `StackEvent`
  gained `OnOff`, `OffWithEffect`, `Level`, `SceneRecalled`, `CheckIn`,
  `FactoryReset`; facade endpoint builders for the Dimmable Light, Dimmer
  Switch, the Trust Center utility endpoint and `with_poll_control`.
* `panweave-green-power`: the GPDF codec (both ApplicationIDs, both frame
  types), GP stub security with every §A.1.5 test vector (CCM* MIC-4,
  nonce, key derivation, TC-LK key protection), the Green Power cluster
  codecs a Basic Proxy needs (GP Notification, GP Commissioning
  Notification, GP Pairing, GP Proxy Commissioning Mode, GP Proxy Table
  Request / Response, Proxy Table entry format), the Proxy Table with
  alias derivation, and the sans-I/O Basic Proxy (pairings, duplicate and
  freshness filtering, key recovery, tunnelling with destinations, aliases
  and delays, commissioning mode); ADR-0011; `green_power` fuzz target.
* Criterion benchmarks (`crypto`, `tlv`, `frame`, `dispatch`), fuzz
  targets for the ZDP security services and the ZCL dispatcher, a
  dispatcher property test, `docs/performance.md`.
* ZDO configuration attributes (`panweave_zdo::ConfigAttributes`, Table
  2-135 defaults) in `StackConfig::zdo`; discovery repeats
  `:Config_NWK_Scan_Attempts` times, `:Config_NWK_Time_btwn_Scans` apart,
  before `JoinFailed` (`Stack::join_with` for an explicit count; BDB
  steering uses one attempt per channel list).
* `panweave-device-library`: the 47 device types of the Device Type
  Library with their mandatory clusters, generated by `cargo xtask codegen`
  from `metadata/devices.toml`; cluster classification and finding &
  binding roles; descriptor validation.
* `panweave` facade: `Coordinator` / `Router` / `EndDevice` builders,
  `Node` (stack + commissioning machine) with the BDB initialization
  procedure, ready-made endpoints, the `two_nodes` example and an
  end-to-end facade test.

### Changed

* On/Off commands are no longer delivered to the application as
  `StackEvent::ZclCommand`: the stack applies them and reports
  `StackEvent::OnOff`; `on_off::apply` takes the current time and
  `panweave_sim::OnOffApp` mirrors the events.
