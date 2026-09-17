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
  Runtime feature `green-power`: `Stack::enable_green_power_proxy()`
  registers the Green Power EndPoint, routes protocol-version-3 MAC frames
  to the stub, tunnels notifications with NWK / APS source aliasing
  (`Nwk::data_request_aliased`, `DataRequest::alias`) after their delay,
  persists the Proxy Table (`Kind::GreenPower`) and reports
  `StackEvent::GreenPowerCommissioningMode`; `Simulator::inject` plays a
  stack-less Green Power Device.
* `panweave-direct`: Zigbee Direct 1.1 secure session establishment
  (Initiator / Responder machines for the four Session Establishment
  messages, SPEKE/Curve25519/AES-MMO-128 and ECDHE-PSK/P-256/SHA-256 with
  MacTag confirmation, the Security Service local TLVs), secured
  characteristic payloads (`SecureChannel`: AES-CCM-128 with the unique
  address, counters and freshness rules), Basic / Admin authorization key
  derivation, the BLE advertisement extension and the GATT identifiers of
  the three services — each checked against the Annex B vectors.
* `panweave-direct::commissioning`: the Commissioning Service (ZD 1.1
  §7.7.2) — Table 27 / Table 44 TLV codecs, Form / Join (with the
  per-method TLV rules of Tables 39–41) / Permit Joining / Leave /
  Commissioning Status / Manage Joiners / Identify / Finding & Binding
  payloads with ZVD-side encoders, and the ZDD handler (`Commissioning`
  over the `Zdd` trait) applying the Table 26 authorization matrix and
  queueing Status Code notifications.
* `panweave-direct::tunnel`: the Tunnel Service NPDU Message TLV
  (§7.7.3) with the trusted-link pre-/post-processing of §7.7.4 and the
  provisioning-session drop rule.
* `panweave::direct` (feature `direct`): `Node` implements the ZDD side
  of the Commissioning Service — formation with the ZVD's parameters,
  joining by association, rejoin or out-of-band adoption, permit
  joining, leave, Manage Joiners provisional link keys, Identify and
  Finding & Binding — reporting completions as `Event::Direct`.
* `panweave-smart-energy`: the profile identifier, cluster identifiers
  (Table 5-14), the per-cluster APS link-key policy `link_key_required`
  (Table 5-12, ADR-0012), the profile parameters of §5.3, and the Key
  Establishment cluster (Annex C): command and certificate codecs for
  both suites, the KDF and MACU / MACV transforms (Annex C.5 / C.6
  vectors), server / client cluster instances and the CBKE initiator /
  responder machines over a host-supplied `Ecmqv` primitive; the
  simulator test runs the exchange over the cluster and proves the
  installed link key with an APS-secured read.
* `panweave-smart-energy::clusters`: Demand Response and Load Control
  (codecs, client attributes and a client-side event scheduler with
  randomization, supersede and cancellation rules), Messaging (codecs
  and the client's message display), Price (Publish Price with its
  optional fields, the client requests and a client-side price table)
  and Metering (mandatory attributes, formatting helpers, Get Profile).
* `panweave-zcl::clusters::measurement`: Illuminance Measurement,
  Illuminance Level Sensing, Temperature, Pressure, Flow, Water Content
  (Relative Humidity / Leaf Wetness / Soil Moisture) and Occupancy
  Sensing servers with default reporting and application setters;
  `ClusterInstance::{i16, set_i16}`; facade endpoints `light_sensor`,
  `occupancy_sensor`, `temperature_sensor`.
* `panweave-zcl::clusters::{time, alarms, power_configuration}`: the
  Time server (monotonic-driven clock, TimeStatus rules, zone / DST and
  derived times, network writes applied with `ZclEvent::TimeSet`), the
  Alarms server (alarm table, Get Alarm / Reset commands executed by the
  dispatcher, `Zcl::raise_alarm` to bound clients with time stamps,
  `ZclEvent::AlarmReset`) and Power Configuration (mains and battery
  attributes, threshold evaluation into `BatteryAlarmState` and alarm
  codes).
* `panweave-zcl::clusters::ias_zone`: the IAS Zone server executed by
  the dispatcher — the three enrolment procedures, Zone Status Change
  Notifications with the Delay field, Zone Enroll Request / Response,
  test mode — with `Zcl::set_zone_status`, `Zcl::request_zone_enrollment`
  and the `ZoneEnrolled` / `ZoneTestMode` events; client-side codecs.
* `panweave-zcl::clusters::color_control`: the Color Control server run
  by the dispatcher — hue / saturation, enhanced hue, XY, colour
  temperature and the colour loop with timed transitions, continuous
  moves and steps, Options handling, scene extension fields and
  `ZclEvent::Color` — plus the `color_dimmable_light` facade endpoint.
* `panweave-smart-energy::devices`: the Smart Energy device descriptions
  (Table 5-13, Tables 6-1 / 6-3 – 6-10) with an endpoint conformance
  checker.
* `Stack` provisioning helpers: `form_network_params`
  (`FormationParams`: key, extended PAN ID, PAN ID, channels, network
  address, update ID), `adopt_network` (`AdoptParams`: join a network
  out of band and resume on it), `leave_with` (RemoveChildren),
  `install_link_key` / `remove_link_key`, and the network-state queries
  `extended_pan_id`, `channel`, `update_id`, `network_key_sequence`,
  `trust_center_address`, `permit_joining_active`, `is_idle`.
  `Nwk::network_formation_with` takes a caller-chosen PAN ID and
  network address.
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

* The runtime's ZCL attribute capacity per cluster instance is 24
  (`Zcl<2, 8, 24>`, `EndpointInstance<8, 24>`) so a full-capability
  Color Control server fits; scene extension field sets hold 32 octets.

* On/Off commands are no longer delivered to the application as
  `StackEvent::ZclCommand`: the stack applies them and reports
  `StackEvent::OnOff`; `on_off::apply` takes the current time and
  `panweave_sim::OnOffApp` mirrors the events.
