# Changelog

All notable changes to Panweave are documented here. The format follows
Keep a Changelog; versions follow SemVer.

## [Unreleased]

Crate versions: `panweave-runtime`, `panweave`, `panweave-sim`,
`panweave-lite`, `panweave-cli` 0.4.0 (new `StackEvent` variants),
`panweave-hub` 0.5.0 (Hub Protocol additions, new `HubConfig` fields),
`panweave-zcl` 0.3.1. The other crates are unchanged since 0.3.0.

### Added

* `panweave-mqtt`: a host bridge from the hub (USB serial, Hub Protocol)
  to an MQTT broker with Home Assistant discovery. Lights, switches,
  contact / water / motion / tamper / battery binary sensors and
  temperature, humidity and battery sensors; a permit-join switch; state,
  availability (Basic read of silent mains devices, 25 h timeout for
  battery ones), light commands and network requests (permit join,
  remove, interview; off with `--no-admin`). Its own MQTT 3.1.1 packet
  codec; `docs/mqtt.md`.
* Hub colour lights, groups and scenes: `LightSetColorTemperature`,
  `LightSetColorXy`, `LightSetHueSaturation` (confirmed by read-back),
  `GetLightColor` and the `LightColorChanged` event (capabilities, mired
  range and colour from the interview, reports and the post-reboot sync),
  `AddGroup` / `RemoveGroup`, group-addressed `GroupLight`, `StoreScene`
  and `RecallScene`; CLI `light … color-temp|xy|hs|color`, `group`,
  `scene`. The MQTT bridge offers colour modes and mired ranges, takes
  `color_temp` / `color` commands, configured groups as lights
  (`--group N=NAME`) and group / scene requests.
* Hub Poll Control: the interview binds Poll Control first; the hub
  answers every Check-in, asking for fast polling while it has work for
  the device (interview, sync, host command, awaited answer), and sends
  Fast Poll Stop when the work is done (`HubConfig::fast_poll_timeout_qs`,
  trace codes `poll-check-in` and `fast-poll-stop`).
  `Zcl::reply_cluster_specific` is public.
* Hub OTA upgrade server: the host offers one image (`OtaOffer`:
  manufacturer code, image type, version, size, optional target, downgrade
  allowed or not) and streams it into a 1 KiB window on demand
  (`OtaDataWanted` / `OtaData`); only matching devices with an older
  version are served, one at a time, with Image Notify to a named target,
  WAIT_FOR_DATA outside the window, fast polling for sleepy devices,
  `OtaProgress` every 5 %, `OtaFinished` (upgrade now, device failure,
  0x95 cancelled, 0x94 timed out), `OtaCancel`, `GetOtaStatus`. The hub's
  endpoint gains the OTA server cluster when the tables have room. CLI
  `ota update <file>` (header checked) / `status` / `cancel`; the MQTT
  bridge publishes `<base>/<id>/ota`.
* Hub install codes: `AddInstallCode { ieee, code }` checks the CRC,
  derives the key (AES-MMO) and installs it at the Trust Center as the
  device's provisional unique key; neither code nor key reaches the trace
  (`install-code-added`). CLI `security install-code`, MQTT
  `bridge/request/install_code`.
* Hub Green Power (feature `green-power`, also of the ESP32-C6
  firmware): the stack's Combo Basic sink on endpoint 242,
  `GreenPowerCommission`, `ListGreenPowerDevices`,
  `RemoveGreenPowerDevice`, events `GreenPowerCommissioning`,
  `GreenPowerPaired`, `GreenPowerRemoved`, `GreenPowerCommand` (once per
  command); GPD command names in `protocol::gp`. CLI `gp`; the MQTT bridge
  makes each GPD a Home Assistant event entity.
* Channels: `Stack::scan_energy` with `StackEvent::EnergyScanned`, and
  `StackEvent::ChannelChanged` when the network manager's channel change
  takes effect. Hub `ScanEnergy` (`EnergyScan` event) and `ChangeChannel`
  (`ChannelChanged`), `HubConfig::energy_detection` (false on the
  ESP32-C6, whose driver cannot measure: scans answer `NotSupported`);
  CLI `network scan` / `network channel`; MQTT `energy_scan` / `channel`
  requests.

### Changed

* ZCL: a server's cluster-specific command to an endpoint without that
  client cluster is handed up as a response (the endpoint sent the
  request as a client) instead of being answered UNSUPPORTED_CLUSTER.

## [0.3.0] - 2026-10-29

Crate versions: 0.3.0 for the crates on the workspace version (new:
`panweave-lite`), `panweave-mac` 0.2.0, `panweave-testkit` 0.2.0,
`panweave-hub` 0.4.0, `panweave-types` 0.1.1, `panweave-storage` 0.1.2.
`panweave-codec` and `panweave-device-library` are unchanged.

### Added

* `panweave-lite`: the stack dimensioned for battery IAS Zone sensors on
  32 KiB microcontrollers (EFR32MG22). `LiteDevice` is the runtime with
  the `SleepySensor` profile plus the BDB machine, an IAS Zone contact /
  water leak endpoint built in place, `ZoneReporter` (delivery tracking,
  back-off retries, an undelivered alarm held before its clear), IAS
  enrolment persistence and `power::plan` sleep planning. 16 320 B of
  static RAM and a 6.7 KiB measured stack peak on Cortex-M33 (QEMU),
  against 148 616 B for the full `Node`; `docs/lite.md`.
* Compile-time profiles: `panweave_types::capacity` (`Capacity`, `Cap<N>`,
  `VecOf`, `DequeOf`); `MacService<D: MacDims>`, `Nwk<C, R, D: NwkDims>`,
  `Aps<C, D: ApsDims>`, `Zdo<D: ZdoDims>`, `Zcl<E, C, A, P: ZclProfile>`
  and `Stack<C, R, S, P: StackProfile, E, CL, A>`, each defaulting to the
  previous dimensions (`FullMac`, `Dims<…>`, `Full`, `FullStack`).
* ZCL `Sensor` profile: cluster states of IAS Zone and Poll Control only,
  four reporting slots per cluster, no scene table, no wide-attribute
  pool; `cluster_state!` defines further state stores.
* `AttributeTable::add_static_string` and `basic::server_static`: Basic
  strings in program memory. `fill_server` variants of the Identify,
  IAS Zone, Poll Control and battery Power Configuration builders for in
  place construction; `power_configuration::battery_server_basic`.
* `ias_zone::renotify`, `Zcl::notify_zone_status`, `ias_zone::Enrollment`
  with `enrollment` / `restore_enrollment`.
* `StackEvent::ZoneDelivery`: the APS outcome of IAS Zone notifications
  and enroll requests (refused or untracked ones reported undelivered).
* `Stack::new_in`, `Stack::unstarted` + `Stack::start_up`,
  `LiteDevice::new_in`: construction in place.
* `Nwk::abort_counter_reservation`, `Aps::abort_counter_reservation`.
* `panweave-sim`: `Device` and `Simulator::add_device` for nodes of other
  stack types on the medium.
* `examples/lite-probe` (EFR32MG22 link build, QEMU mps2-an505 measured
  run), `scripts/lite_footprint.py`, CI job `lite-footprint`, the Lite
  step of `cargo gate`, `conformance/lite-sleepy-end-device.toml`.

### Changed

* ZCL attribute entries are 32 octets (were 80): reporting state moved to
  per-table reporting slots. `AttrMut::configure_reporting` and
  `set_report_timeout` return `Result` (`INSUFFICIENT_SPACE` when a
  profile's slots are taken). Cluster states are read through
  `ClusterInstance::state_ref` / `state_mut` / `set_state`; get-or-create
  helpers return `Option` instead of panicking when a profile cannot hold
  the state. Generic ZCL functions take a second parameter `P`; explicit
  `::<A>` turbofish calls need `::<A, Full>`.
* Table types are dimensioned by `Capacity` types (`NeighborTable<Cap<16>>`
  for `NeighborTable<16>`, likewise the routing, address map, broadcast,
  discovery, joining list, interface, link key, binding, group, duplicate
  and incoming counter tables and `PowerControlTable`).
* `Stack::enable_touchlink` returns whether the profile has touchlink.
* `NorFlashStore` streams records through 64-octet chunks (about 1.6 KiB
  less stack in a compaction) and refuses flashes with a granule above
  64 octets; the runtime's persistence buffers follow the profile.

### Fixed

* A sleepy joiner that received the network key from its parent before
  the Confirm Key of its link-key negotiation restored its old key while
  the Trust Center kept the negotiated one; the authorizing key transport
  now completes the negotiation.
* A failed frame-counter reservation write blocked every NWK- or
  APS-secured transmission until a reboot; it is now retried (nothing is
  secured beyond the committed bound meanwhile).

## [0.2.0] - 2026-10-26

`panweave-hub` 0.3.0, `panweave-storage` 0.1.1.

### Added

* Experimental Telegram notifications in periodic batches (60 s by default):
  door open/close and leak/recovery events share the next check, empty
  intervals leave Zigbee running, and failed deliveries retain their events.
  `alerts configure --interval-ms` keeps `--delay-ms` as a legacy alias.
  Local PowerShell 7 helpers obtain a channel ID and configure a hidden bot
  token without command-line secrets; `docs/telegram-minute-alerts.md`.
* `Node::add_endpoint_with` and `Stack::add_endpoint_with`: register an
  endpoint built in place in the node's tables. `fill` adds the clusters
  and returns the simple descriptor, and a failed fill leaves nothing
  behind. `endpoints::device_into`, `endpoints::trust_center_utility_into`
  and `panweave_hub::hub_endpoint_into` fill an endpoint this way. The
  by-value builders are unchanged.
* `panweave-hub`: a Zigbee hub application on the runtime — bounded
  device registry keyed by IEEE address, device interview (node, active
  endpoint and simple descriptors, Basic attributes, IAS Zone enrolment,
  bindings, reporting, initial state) with retries and resumption for
  sleepy devices, capability and category derivation from descriptors,
  IAS Zone interpretation per zone type, light commands with state
  confirmation, registry persistence through any `Storage`, and the
  Panweave Hub Protocol v1 (typed requests, responses and events, COBS +
  CRC-16 framing, access levels) shared with host applications.
* `panweave-hub-cli`: development client of the Hub Protocol over USB
  serial.
* ESP32-C6 `hub` firmware image with a USB Serial/JTAG transport, a
  registry partition (`partitions-hub.csv`), the RTC watchdog and
  `Board::init_hub` (two stores sharing the flash driver);
  `docs/esp32c6-hub.md`.
* Fuzz target `hub_protocol`.
* ESP32-C6 bring-up and diagnostics (`docs/esp32c6-diagnostics.md`,
  `docs/esp32c6-hardware-testing.md`):
  * `panweave-hub`: structured diagnostic trace (`diag`: 128 packed
    records, severity / category filtering before queueing, drop of the
    least severe first, counted drops, Critical records never filtered);
    instrumentation of joins, interviews, IAS Zone (raw and interpreted
    zone status together), ZCL commands, registry, persistence and the
    host session; boot report, radio, storage and runtime reports;
    bounded radio capture (`capture`) with metadata / sanitized / raw
    modes, sanitized by default (headers only, fail closed on anything
    unrecognized), original lengths kept;
    partition table validation (`partitions`); ESP32-C6 reset reasons
    (`esp32c6`); `NetworkRestore::decide`, the boot network policy.
  * Hub Protocol v1, compatibly extended: requests 0x12–0x1E
    (`GetBootReport`, `GetRadioDiagnostics`, `GetStorageDiagnostics`,
    `GetRuntimeDiagnostics`, `Get/SetTraceConfiguration`, `ReadTrace`,
    `ClearTrace`, `Start/Stop/ReadCapture`, `SetKeyExchangeExemption`,
    `GetSecurityStatus`) and responses 0x09–0x10; no tag renumbered, the
    existing golden frames unchanged.
  * `panweave-hub`: `radio-capture` feature — without it the engine holds
    no capture buffer (2 488 octets less, host measurement) and answers
    the capture requests `NotSupported`; `boot` (`RestoreRetry`,
    `stored_network`), `supervisor` (`RadioSupervisor`), target memory and
    timing metrics in the runtime report (`TargetMetrics`).
  * `panweave-pcap`: `PcapWriter::write_truncated` (captured length below
    the original length).
  * `panweave-runtime`: Trust Center join trace (`join_trace`,
    `Stack::next_join_record`), twelve milestones per queue;
    `Stack::restore_detail` (`RestoreDetail`: empty, incomplete, unknown
    format, malformed).
  * `panweave-nwk`: pending-unicast saturation and high-water counters,
    `Nwk::pending_tx`.
  * `panweave-storage`: `NorFlashStore::stats` (formatted at open,
    damaged records, writes, compactions, I/O errors) and `capacity`.
  * `panweave-hub-cli`: `diagnostics system|radio|storage|runtime|trace|
    watch|device|interview|export|configure|clear`, `capture
    start|stop|export` (pcap, link type 230, JSONL metadata), `self-test`
    (15 tests, PASS / FAIL / SKIP), `hil light|contact|leak` with JSON
    reports, `partitions check`, `security [exempt|revoke]`, global
    `--json`, clean Ctrl+C handling (`ctrlc`), exit codes (3: hub
    unreachable); capture `--mode`, raw only with `--allow-raw`.
  * ESP32-C6 `hub` firmware: boot report (reset reason, chip revision,
    CPU clock, flash size, partition table check, build id from git via
    `build.rs`), radio driver counters, loop and radio-step timing, loop
    overrun records, USB byte counters, capture feed; `capture` feature
    (default); `build.rs` rejects an invalid `partitions-hub.csv`; main
    stack watermark (painted stack) and heap statistics; at most 32
    received frames per radio step.
* Real-device compatibility (`docs/device-compatibility.md`):
  * `panweave-hub`: `compat`, commercial device profiles matched on exact
    Basic identities, with cited evidence and a verification status, for
    the Aqara Water Leak Sensor T1 (`lumi.flood.agl02`), the Sber
    SBDV-00030 opening sensor (`_TYZB01_epni2jgy` / `TS0203`) and the
    Yandex YNDX-00527 leak sensor; all three are documented externally,
    none hardware verified. One correction: the Aqara sensor's MAC
    "mains powered" flag is ignored (it runs on a CR2032). Profiles never
    affect security. The Sber SBDV-00115 bulb is recorded as out of
    scope (Wi-Fi / Bluetooth LE, not Zigbee).
  * `panweave-hub-cli`: `device <ieee> fingerprint [--json]` (every value
    labelled Observed on hardware, Documented externally, Derived from
    protocol semantics or Unknown); `hil aqara-leak|sber-contact|
    yandex-leak` (profile match, fingerprint, battery, alarm and clear,
    battery power cycle, alarm and clear again) with commit, date,
    profile, fingerprint, diagnostics and an overall PASS / FAIL /
    INCOMPLETE result in the report; health, radio recoveries, denied
    frames by reason and exemption use in `diagnostics runtime` and
    `security`.
* `panweave-hub`: `supervisor::HealthSupervisor` (health states
  healthy-idle, healthy-active, degraded, suspected-stall,
  confirmed-stall) replaces `RadioSupervisor`; trace codes
  `stall-suspected`, `stall-confirmed`, `previous-stall-reset`,
  `join-exemption-withdrawn`; `TargetMetrics::health` and
  `radio_recoveries`; `SecurityStatus::denied` (by reason),
  `exemptions_used`, `exemptions_expired`.
* `panweave-runtime`: `Stack::grant_commissioning_exemption`,
  `commissioning_exemption`, `commissioning_exemptions`, `denied_frames`
  (`DeniedFrames`, `DenyReason`), `held_application_frames`;
  `JoinStage::ExemptionWithdrawn`.
* `panweave-aps`: `ApsStats::deferrals`; `constants::LOCAL_RETRY_DELAY`,
  `MAX_LOCAL_DEFERRALS`.
* Experimental, off by default: critical-event notifications over
  Wi-Fi from the ESP32-C6's one radio (Zigbee → Wi-Fi → Zigbee),
  `docs/esp32c6-wifi-alerts.md`. `panweave-hub` feature `alerts`: durable
  bounded event queue with crash-safe delivery acknowledgements and
  explicit overflow accounting, delivery schedule (50 s delay that later
  events cannot postpone, bounded backoff, Telegram `retry_after`,
  mandatory Zigbee time between attempts), Telegram `sendMessage`
  request and response handling, an attempt orchestrator with one
  shared Zigbee-downtime deadline (2 s default) that always restores
  802.15.4 reception, settings and status. Hub Protocol: `GetAlertStatus`
  (0x1F), `SetAlertConfig` (0x20), `QueueTestAlert` (0x21), response
  `AlertStatus` (0x11); `NotSupported` without the feature.
  `panweave-hub-cli alerts status|configure|test` (secrets from standard
  input only), `alerts probe`. `RunRadioProbe` (0x22) and
  `attempt::run_probe`: the radio-switch experiment (802.15.4 off, Wi-Fi
  on and joined, back), refused within 30 s of the previous one.
  `examples/esp32c6-wifi-alerts`: the experimental `hub-wifi` image,
  the same `hub.rs` with `wifi-alerts`, built against a vendored
  `esp-radio` 1.0.0-beta.1 whose "802.15.4 and Wi-Fi" build guard
  becomes the opt-in feature `panweave-sequential-radio` (no driver
  code changed); it runs the experiment (`esp-rtos`, `Radio::suspend`
  and `Radio::resume`, `wifi_switch`) and delivers notifications:
  DHCP, DNS and TCP over `embassy-net`, TLS 1.3 over `embedded-tls`
  with Go Daddy Root G2 pinned and the chain limited to one
  intermediate. `AlertStatus::wifi_failure`: the driver's disconnect
  reason and the access point's signal for a failed join, shown by
  `alerts probe` and `alerts status`. A probe scans before it joins
  (stage `scan`): the access points heard, the strongest six, and the
  configured SSID with its channel, signal and security. The result is
  shown after each probe and by `alerts scan` (`GetWifiScan`, 0x23;
  response `WifiScan`, 0x12), each access point with its BSSID.
  Access-point pin: `alerts configure --wifi-bssid`, `--wifi-channel`,
  `--wifi-wpa3-only` (`AlertConfigUpdate::{bssid, channel, wpa3_only}`,
  also in `AlertStatus`). It is persisted as an optional tail of the
  existing settings record. WPA3-only uses a second patch of the
  vendored esp-radio, `AuthenticationMethodConfig::Wpa3Personal`, but
  cannot join with the crates.io driver: the station side of SAE is
  compiled out of the `esp-wifi-sys-esp32c6` 0.3.0 supplicant (reason
  210 on a board). `hub-wifi` therefore uses a vendored
  `esp-wifi-sys-esp32c6`. Its supplicant is rebuilt with SAE on software
  mbedTLS: the recipe of esp-wireless-drivers-3rdparty#11 applied to the
  C6, from the same ESP-IDF, whose baseline build reproduces the shipped
  libraries byte for byte (`examples/esp32c6-wifi-alerts/wpa3-supplicant/`).
  `hub-wifi` joins WPA3-Personal only: PMF is required, SAE uses H2E when
  offered and hunt-and-peck otherwise, and transition-disable is
  honoured. A join that heard no access point is retried within the
  budget. +118 KiB flash. A probe reports a
  directed SSID scan, which hidden networks answer. `wifi-scan-check`, a
  diagnostic image, compares Wi-Fi reception before and after
  802.15.4: no degradation measured. On a board the join reaches SAE and
  ends in reason 202 (authentication failed). It has not yet joined. A
  stage that runs out of time is now reported as `budget-exhausted`, no
  longer `stage-failed`. On a board the image boots, and a
  probe switches the radio and back in about 1.6 s. No join has
  succeeded yet.
* `panweave-sim`: `Simulator::node_count`.

### Changed

* ESP32-C6 `hub` firmware: a new network is formed only when the stack's
  storage was read and is genuinely empty. A read error, damaged records,
  or a stored network that cannot be used (half written, unknown format,
  undecodable — which 0.2.0 treated as factory new) leave the hub up
  without a network and report it; an unreadable storage is read again
  with a growing interval and the network resumes when a read succeeds.
  0.2.0 formed a new network on a read error, orphaning paired devices.
* ESP32-C6 `hub` firmware: the watchdog is fed every loop turn unless the
  health supervisor has evidence of a stall its recovery did not fix: a
  stack deadline overdue for 10 s, or transmissions handed to the driver
  that never complete for 30 s while frames are queued. Silence is never
  such evidence, so an idle network or one with only sleepy sensors never
  resets the hub (an earlier unreleased build reset after 120 s without
  a transmission). A suspected stall first re-arms the radio (no flash
  write, no network change); only a confirmed one resets, its cause is
  stored and reported once by the next boot, and a boot that followed a
  watchdog reset never escalates again (no reset loops).
* `panweave-hub`: an IAS zone status that arrives before the zone type is
  interpreted as soon as the type is known; a compatibility profile's
  power-source correction applies once the identity is read.
* `panweave-runtime`: the Trust Center's link-key table holds 32 entries
  (`LINK_KEYS`; 8 with `small-tables`), as many devices as the hub
  registers.
* `panweave-security`: `TrustCenterPolicy::node_join_timeout_s`
  (`bdbTrustCenterNodeJoinTimeout`, default 15).

### Security

* `panweave-runtime`: `bdbTrustCenterRequireKeyExchange` is enforced
  (`authorization`). A device that received the network key is pending
  until it holds a verified unique Trust Center link key (APS key
  exchange, dynamic link key negotiation, Smart Energy CBKE or swap-out
  renewal); meanwhile its application frames are dropped and
  `StackEvent::DeviceAuthorized` is not raised (`KeyExchangePending`
  instead); after `node_join_timeout_s` its link key is removed and it is
  asked to leave (`KeyExchangeTimedOut`). Authorization is derived from
  the persisted key-pair entry, so a restart never promotes a pending
  device. Per-device exemptions (`Stack::set_key_exchange_exemption`)
  are the only relaxation. Previously the flag was never read and every
  device that received the network key was authorized.
* `panweave-runtime`: TCLK Request Key honours
  `allowTrustCenterLinkKeyRequests` (previously only "never" was checked,
  so a verified device could replace its key at will); a device inside
  its key-exchange window may repeat its request, and a device restored
  from a swap-out backup may renew its key once.
* `panweave-hub`: devices without application access are neither
  registered nor interviewed; administrator exemptions are Admin-only,
  bounded in time until the device joins, persisted with it, at most 8.
* `panweave-hub`: radio capture no longer relies on NWK security to decide
  what is safe to export: sanitized captures keep headers only.
* `panweave-runtime`: every application frame (APS data outside ZDO) is
  decided on its originator: admitted only from an authorized or
  admitted-exempt device; an originator whose IEEE address is unknown is
  held (2 frames, 10 s) while the Trust Center asks for it and refused
  if it cannot be resolved; a claimed address that contradicts the
  address map, a source without a key-pair entry, and pending or
  incomplete devices are refused, counted by reason. Group and broadcast
  frames follow the same rule. Green Power infrastructure frames (alias
  sources) and Key Establishment for pending devices are the documented
  exceptions. Previously frames whose source could not be attributed
  were delivered.
* `panweave-runtime`: key-exchange exemptions are a single-use
  commissioning grant (at most 3600 s, never extended by a repeated
  request, not restored after a restart) consumed by the device's
  initial join, then an admission that a new unsecured join withdraws;
  removing a device revokes its exemption and key. An exemption cannot
  authenticate a claimed IEEE address (documented limitation).

### Fixed

* ESP32-C6 hub images: the stack frame of `main` no longer holds the
  boot-time copies of the endpoints. They were built by value and passed
  down, so a 51 KiB endpoint was copied about three times; the frame was
  about 370 KiB. The experimental `hub-wifi` image has 322 KiB of stack,
  and it panicked in `esp_hal::init` ("stack pointer out of range") and
  rebooted in a loop. The normal `hub` had 396 KiB and, by the frame
  sizes, overran it while adding its endpoints. The frame of `main` is
  now about 190 KiB in both, and the boot peak about 240 KiB. The fixed
  `hub-wifi` boots on a board.
* `panweave-aps`: a frame the NWK layer refuses for lack of buffers (its
  pending table full, typically with frames held for sleepy children) is
  offered again after 1 s, at most 8 times, acknowledged or not;
  previously an acknowledged frame spent all its retries in the same
  turn and an unacknowledged one failed at once. Three sleepy sensors
  pairing together lost Trust Center key-exchange replies and were
  removed for not completing the key exchange; they now all complete
  (`hub_devices` tests). `PENDING_TX` stays 4.
* `panweave-hub`: a BatteryPercentageRemaining above 200 (out of range)
  is ignored instead of being shown as 100 %.

### Removed

* ESP32-C6 crate feature `legacy-joiners`: it cleared the Trust Center's
  `require_key_exchange` flag, which was not enforced then. The
  requirement is enforced now; a legacy device is admitted only through
  an explicit, per-device exemption (`security exempt`).

## [0.1.0] - 2026-09-18

The first release: the stack as inventoried in `docs/conformance.md`.

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
* Power Configuration battery sources 2 and 3 (`add_battery_source`,
  `set_battery_source`, `battery_attr`, ZCL8 Table 3-27) and the mains
  voltage dwell timer (§3.3.2.2.2.2): `set_mains_voltage` takes the
  time, arms `MainsVoltageDwellTripPoint` and the dispatcher raises the
  alarm through the endpoint's Alarms server when the excursion
  persists.
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
* `panweave-zcl::clusters::diagnostics` with `Stack::refresh_diagnostics`
  feeding the stack's counters; the facade instantiates Diagnostics,
  Alarms, Time, Power Configuration and IAS Zone servers / clients for
  device types that list them.
* `panweave-zcl::clusters::hvac`: the Thermostat core (setpoint limits,
  dead band and control-sequence rules on writes, Setpoint Raise/Lower
  with `ZclEvent::Setpoints`, running mode, scene fields) and Fan
  Control; facade `thermostat_device` endpoint.
* `panweave::smart_energy_drivers::trust_center::SeTrustCenter` (SE
  1.4a §5.4.1, §5.4.2, §5.5.5.5): the Trust Center registry over a
  `Stack` — install-code provisioning installing the provisional unique
  link key, the permit-join broadcast schedule (254 s at most, every
  240 s and on every Device_annce), joins / leaves / Key Establishment
  results tracked, hashed-key backup records, key retirement,
  de-registration and the removal of devices that never establish a
  key.
* `panweave::smart_energy_drivers::commissioning::SeCommissioning`
  (SE 1.4a §5.5.5): the device life-cycle over a `Stack` — the
  auto-join scan schedule driving `Stack::join`, CBKE through
  `CbkeDriver`, ESI discovery with a Smart Energy Match_Desc_req,
  Bind_req (with IEEE_addr_req) for every client cluster at every ESI,
  periodic rediscovery, rejoin and recovery on `TrustCenterLost`, Key
  Establishment with a replacement Trust Center after a detected
  swap-out (one retry, then leave), and the leave reset;
  `SeCommissioningEvent` reports the milestones.
* `panweave::smart_energy_drivers` (feature `smart-energy`): Smart
  Energy cluster models bound to a `Stack` the way `CbkeDriver` is —
  `messaging::{MessagingClient, MessagingServer}` (SE 1.4a Annex D.5)
  decode the cluster's commands from stack events, drive the Display /
  Server models, send the responses APS link-key protected and report
  `MessagingEvent` / `MessagingServerEvent`; `drlc::{DrlcClient,
  DrlcServer}` (Annex D.2) schedule and issue load control events,
  send the Report Event Status frames after their 0–5 s delay, answer
  Get Scheduled Events and report `DrlcEvent` / `DrlcServerEvent`;
  `price::{PriceClient, PriceServer}` (Annex D.4 core) store and
  acknowledge published prices and answer Get Current Price / Get
  Scheduled Prices from the new server-side
  `clusters::price::PriceSchedule`; `metering::{MeteringServer,
  MeteringClient}` (Annex D.3) answer Get Profile from the new
  `clusters::metering::ProfileLog`, fast poll, sampling, snapshot,
  supply-control and mirror requests, and issue / report them on the
  client;
  `UtcClock` and `utc_now` supply UTC from the endpoint's Time server
  or the application.
* A panweave stack as a Zigbee Direct Virtual Device (ZD 1.1 §7.7.4.3,
  §7.7.4.6, §8.4.3.3): `Stack::join_via_trusted_link` joins (initial
  join, secured rejoin or Trust Center rejoin) through a ZDD's tunnel,
  the ZDD becoming the parent behind the Trusted Link
  (`Nwk::join_via_trusted_link`, the Network Commissioning Request
  carrying the Device Capability Extension), the Basic authorization
  key completing the join without a network key
  (`Nwk::authorize_without_network_key`), and an end device's
  broadcasts going to a parent behind a link over the link.
* Generic Tunnel 0x0600, BACnet Protocol Tunnel 0x0601 and ISO 7816
  Protocol Tunnel 0x0615 (ZCL8 §9.2, §9.3, §9.5):
  `panweave_zcl::clusters::tunnels` with the Table 9-2 / 9-25
  attributes, the Match Protocol Address / Response, Advertise Protocol
  Address, Transfer NPDU and Transfer APDU codecs, the server builders
  and the dispatcher answering a Match Protocol Address that equals
  `ProtocolAddress` with the device's IEEE address (`Zcl::set_ieee`,
  set by the runtime) and Insert / Extract Smart Card with the `Status`
  rules.
* Partition cluster 0x0016 (ZCL8 §9.6): `panweave_zcl::clusters::partition`
  with the Table 9-29 attributes and their derived defaults
  (`Params::defaults`), the TransferPartitionedFrame / MultipleACK /
  Read- and WriteHandshakeParam codecs, and the sans-I/O `Sender`
  (blocks in `NumberOfACKFrame` groups, resends of the blocks a
  MultipleACK names, `NumberOfSendRetries` on `SenderTimeout`) and
  `Receiver` (reassembly, MultipleACK on a complete group or at
  `NACKTimeout`, abandonment at `ReceiverTimeout`); `endpoints::server`
  / `client(0x0016)`.
* Prepayment friendly credit periods (SE 1.4a D.7.2.2.1.13,
  D.7.2.2.1.17–D.7.2.2.1.18, D.9.2.3.2.3.2 and the glossary's delivery
  rule): `FriendlyCreditPeriod::evaluate` reads the Friendly Credit
  calendar's day profiles around an instant (active, end, next start,
  `RemainingFriendlyCreditTime`), `FriendlyCreditTracker` applies the
  rule (a period entered with credit keeps the supply on, one entered
  disconnected does not, the balance decides again at the end) and
  raises the Friendly Credit In Use / Period End Warning alarm bits;
  `panweave_smart_energy::civil` (UTCTime calendar arithmetic, shared
  with the metering snapshot schedules).
* Prepayment alarm codes and historical costs (SE 1.4a D.7.2.2.5,
  D.7.2.2.6): `prepayment::alarm_code` (the codes of Tables D-140 to
  D-142 with `mask_bit` / `enabled` mapping each to its alarm mask
  attribute and bit) and `prepayment::historical_cost` (the Table D-143
  attribute set with `previous_day` / `previous_week` /
  `previous_month`).
* Metering block information snapshot sub-payloads (SE 1.4a Figures
  D-21 / D-22 / D-25 / D-26, payload types 2, 3, 6, 7): `BlockSnapshot`
  with the tier × block summations behind the "Number of Tiers and
  Block Thresholds in Use" bitmap.
* Metering two-way mirror notification flags (SE 1.4a D.3.4.4.3,
  D.3.3.3.1.10): `metering::notification` (the Notification attribute
  set of Table D-58 with the bits of Tables D-59 and D-69–D-72), the
  predefined schemes A / B as Notification Flag Orders
  (`notification_scheme::{ORDER_A, ORDER_B, predefined_order,
  flag_numbers}`), `Mirror::{notification_flags, configured_scheme,
  report_response}`, `MirrorTable::{notify, configure_scheme}`,
  `MirrorReportAttributeResponse::for_order`; the ESI's `MeteringClient`
  driver mirrors a meter's Report Attributes into the mirror endpoint's
  Metering server, answers with the MirrorReportAttributeResponse when
  notification reporting is on and takes Configure Mirror /
  ConfigureNotificationScheme on mirror endpoints
  (`MeteringEvent::{MirrorReported, SchemeConfigured}`); the meter's
  `MeteringServer::report_to_mirror` and
  `MeteringServerEvent::NotificationFlags`.
* Metering snapshot schedules (SE 1.4a D.3.3.3.1.5, D.3.4.5):
  `SnapshotSchedules` stores the schedules of a Schedule Snapshot with
  the Table D-50 confirmations, `next_snapshot_time` works the Table
  D-65 bitmap out on a civil calendar (daily / weekly / monthly, at the
  start or end of the unit or exactly `frequency` units apart), and the
  `MeteringServer` driver answers Schedule Snapshot, takes each
  scheduled snapshot when due and publishes it to the scheduling client
  (`Snapshots::publish`); `MeteringClient::schedule_snapshot` and
  `MeteringEvent::SnapshotsScheduled`.
* Metering demand limiting and uncontrolled-flow detection (SE 1.4a
  D.3.2.2.7, D.3.3.3.1.15): `SupplyControl::demand_limiting`
  (`DemandLimiting`, `DEMAND_LIMIT_OFF`), `demand_measured` (an
  excursion over `DemandLimit` disconnects the supply into the
  load-limit state, counts, and `poll_demand_limit` re-arms it after
  `DemandLimitArmDuration`), `flow_measured` (a flow at or above the
  uncontrolled-flow threshold for the stabilisation and measurement
  periods raises the uncontrolled-flow event); the `MeteringServer`
  driver's `demand_measured` / `flow_measured` keep
  `CurrentDemandDelivered` and the Supply Limit attributes current, and
  `panweave_smart_energy::endpoints::add_supply_limit` instantiates the
  attribute set.
* The ZDD's security state (ZD 1.1 §6.2, §6.3.1, §6.6):
  `panweave_direct::state::SecurityState` (Open to be provisioned for
  `NewZddProvisioningTimeout`, at least 60 s, held open by a provisioning
  session; interface Off; Open to connect once on a network; leaving
  reopens provisioning; the Configuration cluster switches the
  interface) with `admit` (authorization keys only once provisioned,
  new ZVDs only while the network is open, the anonymous secret only
  while the Anonymous Join Countdown Timer runs, no provisioning session
  for a ZVD holding an authorization session); the facade's
  `Node::direct_power_up` (run by `initialize`), `direct_admit`,
  `direct_session_opened` / `direct_session_closed`,
  `DirectState::security`, `NEW_ZDD_PROVISIONING_TIMEOUT` and
  `Event::DirectAdvertising` telling the host when to advertise.
* The ZVD's tunnel client (ZD 1.1 §8): `panweave_direct::zvd::TunnelClient`,
  a sans-I/O machine over the host's BLE scan / connect / session /
  tunnel primitives that discovers a ZDD of the ZVD's network by its
  advertisement (§8.3.1), reconnects to known ZDDs, retries discovery at
  least once and moves to another ZDD when a session fails (§8.3.3),
  and sends the Network Commissioning Request the situation calls for
  (initial join, secure rejoin, or a Trust Center rejoin after a key
  rotation, adopting the address of an address-conflict response);
  `zvd::random_eui64` (locally administered, §8.5) and
  `zvd::random_short_address` (R23.2 §3.6.1.8).
* Zigbee Direct legacy-network support (ZD 1.1 §10, ADR-0017 decision
  8): `panweave_direct::legacy` (APS frame shape, the well-known-key
  probe, the ephemeral authorization session with its §10.1 filter,
  watch and timeout), `KeyDescriptor::EphemeralAuthorization` (0xB0 /
  0xB1, no descriptor) with `TransportedKey` /
  `StackEvent::EphemeralAuthorizationKey`,
  `Aps::transport_authorization_key_as_trust_center` (NWK source
  aliased to 0x0000, key-load under the well-known key); a ZDD whose
  Trust Center is not Zigbee Direct aware swallows the tunnelled network
  key, sends a global or unique ephemeral key, passes only the ZVD's
  exchange with the Trust Center, routes on its behalf as for an end
  device, sends the Basic key once the Trust Center's key-load and
  data-key secured messages were seen (`Node::direct_legacy_session`),
  drops a ZVD that never authenticates
  (`Event::DirectAuthorizationTimeout`) and answers a Trust Center
  rejoin with a Basic key derived from the active network key.
  `StackConfig::zigbee_direct_aware = false` makes a Trust Center behave
  like one predating Zigbee Direct, for interoperability tests.
* A ZVD operating as Trust Center and ZVD rejoins through the ZDD (ZD
  1.1 §7.7.4.4, §7.7.4.6; ADR-0017 decisions 6–7): the Network
  Commissioning Request of type Establish Trusted Link (R23.2 Table
  3-64) attaches the configured Trust Center behind the Trusted Link as
  a router neighbour at 0x0000 (`NwkEvent` / `StackEvent::TrustCenterLinked`,
  no join indication, refused for anyone else or unsecured), neighbours
  behind a link are exempt from Link Status aging and a reply to a frame
  received over a link goes back over it; `Nwk::set_security_model`
  replaces `set_distributed` and is kept in step by the runtime (so
  unsecured rejoins on distributed networks are refused as §3.6.1.6.1.3
  asks); the Trust Center admits a virtual device's secure rejoin
  without a key transport and answers its Trust Center rejoin with a
  fresh Basic key.
* The ZVD chooses the security model of a formed network (ZD 1.1
  §7.7.2.5, Table 36): `Stack::set_security_model(distributed)` switches
  an idle node between distributed security and, for a coordinator,
  centralized security with itself as Trust Center; the ZDD's Form
  Network follows the Trust Center Address TLV (a router-only ZDD refuses
  a centralized network). A joiner's `StackConfig::distributed` now
  follows the network it joined (learnt from the Transport Key).
* Zigbee Direct out-of-band join follow-up (ZD 1.1 §7.7.2.7.4) and the
  Admin key hand-off (§6.3.2.1): `Stack::update_trust_center_link_key`
  runs the On-Network TCLK Update procedure on demand and
  `Stack::trust_center_link_key_is_provisional` reports the key state;
  a ZDD adopted with a provisional Trust Center link key updates it once
  on the network, stays on the network when the Trust Center is out of
  reach and retries every `TCLK_UPDATE_RETRY`
  (`Node::direct_tclk_update_pending`); `Node::admin_key_for(zvd)` is
  the provisioned Admin key (`Kind::DirectAdminKey`, restored by
  `initialize`, erased by a factory reset) or the key derived from the
  active TCLK on a centralized network. A factory reset now also erases
  `Kind::DirectConfig` and resets the Zigbee Direct state.
* Zigbee Direct Configuration cluster 0x003D (ZD 1.1 §11.3) and the ZDD
  interface state: `panweave_zcl::clusters::direct_configuration`
  (`InterfaceState`, `AnonymousJoinTimeout`, Configure Zigbee Direct
  Interface with its response, Configure Anonymous Join Timeout;
  accepted APS-secured from the Trust Center of a centralized network,
  `Zcl::set_trust_center`, NOT_AUTHORIZED otherwise), `ZclEvent` /
  `StackEvent::{DirectInterface, DirectAnonymousJoinTimeout}`,
  `Kind::DirectConfig`; the facade's `Node::enable_direct_configuration`,
  `direct_interface_enabled`, `anonymous_join_allowed` (the Anonymous
  Join Countdown Timer of §11.3.5.4.4, restarted on power-up and
  reconfiguration), `persist_direct_config` / `restore_direct_config`
  (run by `initialize`) and `check_direct_aware` (the Match_Desc_req of
  §6.2.3 for the client cluster on the Trust Center,
  `DirectState::trust_center_aware`); `endpoints::client(0x003D)`.
* Zigbee Direct Virtual Device admittance (R23.2 §4.6.3.2.2.4, ZD 1.1
  §7.7.4.3, §7.7.4.8, §9; ADR-0017): `KeyType::{EphemeralUnique,
  BasicAuthorization, AdministrativeAuthorization}`,
  `KeyDescriptor::BasicAuthorizationKey`,
  `Aps::transport_basic_authorization_key`,
  `panweave_security::authorization::{basic_key, admin_key}` (Annex B.3
  vector) and `StackEvent::BasicAuthorizationKey`; a Trust Center with
  `allow_virtual_devices` answers a joiner whose Joiner Encapsulation
  carries the Device Capability Extension ZVD flag with a Basic
  authorization key under the key-load key instead of the network key,
  refuses it otherwise, and sends every virtual device a fresh Basic key
  on a network key update; on a distributed network the ZDD router
  hands the ZVD its Basic key under the distributed global link key
  (§7.7.4.5); the ZDD facade drops tunnelled Network
  Commissioning Requests without the flag and reports
  `Event::DirectTunnelDeclined` instead of tunnelling a frame that
  conveys a network key.
* Trusted Links (R23.2 §3.2.2.41–§3.2.2.44) and the Zigbee Direct
  Tunnel Service binding (ZD 1.1 §7.7.3–§7.7.4): `NeighborEntry::link`
  marks a neighbour reached over a Trusted Link, `Nwk::on_trusted_link_data`
  processes an NPDU received over it (no auxiliary header; treated as
  NWK-secured when `assume_security`; a joiner heard over the link stays
  behind it), unicasts to such neighbours and copies of broadcasts leave
  as `NwkAction::TrustedLinkData` (plaintext, security bit clear, the
  link asked to stand in for NWK security); the runtime exposes
  `Stack::{add_trusted_link, remove_trusted_link, on_trusted_link_npdu}`
  and `StackEvent::TrustedLinkNpdu`; the facade (feature `direct`) binds
  the tunnel with `Node::{open_tunnel, on_tunnel_write, close_tunnel}`
  and `Event::DirectTunnel`. A ZVD joins with a Network Commissioning
  Request over the tunnel and exchanges NWK frames with the network
  through the ZDD.
* OTA client periodic polling (ZCL8 §11.8.2, §11.13.4):
  `ota::Client::with_query_period` makes an idle client send Query Next
  Image every period (the cadence each application standard sets),
  re-armed after every answer.
* Green Power (GP 1.1.2): the SelectedSender proxy switches to the GPD's
  transmit channel for up to 5 s after a GP Response for another
  channel, answers the Channel Request there with the queued Channel
  Configuration GPDF without forwarding it, and returns to the
  operational channel (§A.3.9.1 steps 8–9; `Stack::green_power_channel`,
  `Proxy::set_away`); a Device_annce / Update Device naming a GPD alias
  of this proxy or sink for a real device is answered with the alias
  Device_annce after Dmin + RAND(Dmax) (§A.3.5.2.3, §A.3.5.2.5). The
  simulator records the transmit channel in its trace
  (`TraceEntry::channel`) and moves the injected radio with
  `Simulator::set_injector_channel`.
* Metering attribute sets (SE 1.4a Annex D.3.2.2): `metering::{tou,
  load_profile, supply_limit, block, alarm, billing, supply_control,
  alternative}` give the TOU tier and block summation identifiers (as
  functions of tier / block), the Supply Limit, Alarms, Meter Billing and
  Supply Control attribute definitions and the alternative historical
  counterparts. `SupplyControl` applies SetSupplyStatus (the status
  required after tamper / depletion / uncontrolled-flow / load-limit
  events, newer issuer event ids only), SetUncontrolledFlowThreshold and
  ResetLoadLimitCounter, and answers meter events (`SupplyEvent`) with
  the required status while counting load-limit events; the facade
  `MeteringServer` handles the three commands (mirroring the policy into
  the Supply Limit / Supply Control attributes when the endpoint carries
  them) and exposes `supply_event`; `MeteringClient` sends them.
* `SeCommissioning` leaves the network when Key Establishment ends with
  UNKNOWN_ISSUER (SE 1.4a §5.4.7.1) instead of retrying.
* Smart Energy key refresh policies (SE 1.4a §5.4.4, §5.4.5):
  `Aps::{mark_key_stale, clear_key_stale, is_key_stale}` retire a link
  key from data traffic (secured data frames dropped without an
  acknowledgement and reported as `ApsEvent::StaleKeyUsed` /
  `StackEvent::StaleLinkKeyUsed`, APS commands still processed);
  `Stack::random_key` and `Stack::short_of`; `SeTrustCenter` gains
  `link_key_lifetime` (keys retired on expiry, `KeyRetired`, a stale key
  in use answered with `Renegotiate` for the application's
  `CbkeDriver::start`) and `network_key_period` (a random network key
  broadcast and switched periodically, `NetworkKeyUpdated`).
* `panweave::endpoints::validate_for` accepts a sleepy device without
  the Groups and Scenes servers (DTL §1.11.1).
* RSSI Location cluster (ZCL8 §3.13): `clusters::rssi_location` with
  the Location Information and Location Settings attributes, codecs
  for every command (absolute location, device configuration and its
  response, Get Location Data, location data response / notification /
  compact notification, RSSI response, Send Pings, anchor announce,
  RSSI ping / request, Report RSSI Measurements, Request Own Location)
  and a server the dispatcher runs: Set Absolute Location / Set Device
  Configuration applied (the latter refused for an absolute location),
  Get Device Configuration and Get Location Data answered for the
  device's own address (NOT_FOUND otherwise, silent when only absolute
  locations are wanted), repeated responses as (compact) notifications
  every ReportingPeriod, ping blasts on Send Pings, RSSI Responses
  collected and reported after CalculationPeriod, the periodic
  notification, `ZclEvent::{LocationRecalculate, AnchorNode}` (also
  `StackEvent`) and `Zcl::{rssi_location_measured,
  rssi_location_absolute, rssi_request, rssi_request_own_location}`.
* Power Profile cluster (ZCL8 §3.17): `clusters::power_profile` with
  the five attributes, codecs for every command (energy phases, profile
  records, prices, schedules, constraints, the extended price request)
  and a server keeping up to four profiles; the dispatcher answers Power
  Profile Request (one response per profile), Power Profile State
  Request, Schedule Constraints Request and Energy Phases Schedule
  State Request, applies Energy Phases Schedule Notification / Response
  (NOT_AUTHORIZED without remote control or activation delay, the
  profile moving to ENERGY_PHASE_WAITING_TO_START, a schedule state
  notification when it changed) and hands prices to the application
  (`ZclEvent::{PowerProfilePrice, PowerProfileOverallPrice,
  PowerProfileScheduled}`, also `StackEvent`); the application drives
  `Zcl::{power_profile_set, power_profile_state,
  power_profile_set_remote, power_profile_constraints,
  power_profile_request_schedule, power_profile_get_price,
  power_profile_get_price_extended, power_profile_get_overall_price}`.
* Device Type Library builders `panweave::endpoints::white_goods` and,
  with the `smart-energy` feature, `home_gateway`, `smart_plug`,
  `meter_interface` and `consumption_awareness` (the Metering cluster
  comes from `panweave-smart-energy`); every device type of the library
  is now instantiable.
* Appliance Management clusters (ZCL8 Chapter 15) and Meter
  Identification (§10.13): `clusters::appliance::{control,
  identification, events_alerts, statistics}` with their attributes,
  command codecs and server state (signal state, alert list, log queue),
  answered by the dispatcher (Signal State, Get Alerts, Log Request, Log
  Queue Request) and driven by the application through
  `Zcl::{appliance_signal_state, appliance_alert, appliance_event,
  appliance_log, appliance_statistics_available}` and the
  `ApplianceCommand` / `ApplianceOverload` events (also `StackEvent`);
  `clusters::meter_identification` with the Table 10-215 attributes.
  The facade instantiates all five clusters.
* Endpoint validation (DTL §2.3, ZCL "M/O" columns):
  `panweave_zcl::requirements` lists the unconditionally mandatory
  server attributes and received commands of every implemented cluster;
  `panweave::endpoints::validate` checks a simple descriptor and its
  endpoint instance against the device type's mandatory clusters and
  those requirements, reporting `Deficiency::{UnknownDeviceType,
  MissingCluster, NoInstance, MissingAttribute, MissingCommand}`.
* GPD Application Description and Compact Attribute Reporting (GP
  1.1.2 §A.4.2.1.6, §A.4.2.3.6): `description::{ApplicationDescription,
  ReportDescriptor, DataPoint, AttributeRecord, Descriptions,
  CompactReport}` decode and build the report descriptors, assemble
  them per GPD and interpret a compact report into attribute values;
  the sink defers a multi-sensor pairing until the description is
  complete (step 13.i) and the runtime delivers compact reports to the
  paired endpoints as Report Attributes (`StackEvent::ZclReport`).
* GP Pairing Configuration (GP 1.1.2 §A.3.3.4.6, §A.3.5.2.4.1): the
  codec (`cluster::{PairingConfiguration, ConfigurationAction,
  PairedEndpoints}`, sharing the Sink Table entry body) and
  `Sink::on_pairing_configuration` applying no-action / extend /
  replace / remove-pairing / remove-GPD with the security and
  communication-mode checks, the paired local endpoints
  (`SinkEvent::LocalEndpoints`, honoured by the runtime when executing
  the GPD's commands), GP Pairing on request and the group / announce
  follow-ups; the application description action is refused.
* Green Power proxies act as SelectedSender (GP 1.1.2 §A.3.9.1 steps 8,
  9, 14): `Proxy::on_response` stores the GP Response's GPD command in
  the shared gpTxQueue (`tx_queue::{TxQueue, GpdfTx, build_data_gpdf,
  build_maintenance_gpdf}`), `Proxy::next_gpdf` hands out the
  Commissioning Reply / Channel Configuration gpTxOffset after the GPD's
  receive window, and the runtime transmits it; a frame appointed for
  another channel is dropped (`TODO(PW-GP-CHANNEL)`).
* Runtime Green Power Basic Combo (feature `green-power`):
  `Stack::enable_green_power_sink(SinkOptions)` registers endpoint 242 as
  GP Combo Basic with the Table 24 server attributes, restores the
  persisted Sink Table (`Kind::GreenPower` ids 0x100+),
  `green_power_commission` / `green_power_stop_commissioning` drive the
  sink's commissioning mode, the sink's GP Pairing / Proxy Commissioning
  Mode / Response / Sink Table Response go out from the Green Power
  EndPoint, its Commissioning Reply and Channel Configuration GPDFs are
  transmitted after gpTxOffset, the alias is announced with Device_annce
  (NWK sequence and APS counter 0x00), endpoint 242 joins the pairing's
  group, and accepted GPD commands are reported as
  `StackEvent::GreenPowerCommand` and executed on the paired local
  endpoints through their generic ZCL translation;
  `StackEvent::{GreenPowerPaired, GreenPowerDecommissioned,
  GreenPowerRefused}`; `Simulator::{block_injector, unblock_injector}`.
* `panweave_green_power::sink::Sink` (GP 1.1.2 §A.3.5.2.4, §A.3.9): the
  sans-I/O Basic Combo sink — commissioning mode (local or GP Sink
  Commissioning Mode, proxies involved on request), unidirectional and
  bidirectional commissioning from direct GPDFs and GP Commissioning
  Notifications with the gpsSecurityLevel policy, TC-LK protected key
  exchange, Commissioning Reply delivery from its own gpTxQueue or by GP
  Response to a proxy, Success verification, GP Pairing generation,
  decommissioning, operation with duplicate / freshness filtering and
  wrong-mode corrections, Channel Request answers, GP Sink Table
  Response; `translation::translate` maps the Table 54 / 55 GPD commands
  to ZCL; ADR-0016.
* Green Power sink-side codecs (GP 1.1.2 §A.3.3, §A.4.2.1): the Sink
  Table entry format and `SinkTable` (`sink_table`), the GPD
  Commissioning / Commissioning Reply / Channel Request / Channel
  Configuration payloads (`commissioning`), GP Sink Commissioning Mode,
  GP Response, the Sink Table Request / Response aliases, the sink
  attribute identifiers, `BASIC_SINK_FUNCTIONALITY`, `SinkSecurityLevel`
  and the `exit_mode` flags.
* `panweave::cbke::CbkeDriver` (SE 1.4a Annex C, BDB 3.1 §8.7): runs
  the Key Establishment exchange over a `Stack` on either side — the
  initiator by itself after joining with `start_after_join`, the
  responder for any peer that initiates — with the C.3.1.1 timeouts,
  NO_RESOURCES while busy, and the derived link key installed as the
  verified unique key (`CbkeOutcome`); `Stack::{trust_center_short,
  ieee_of}` and the machines' `into_ecmqv` / `suite` support it.
* Color Control completion (ZCL8 §5.2.2.2): the Defined Primaries and
  Additional Defined Primaries sets (`enable_primaries`, up to six),
  the Defined Colour Points set with the white point
  (`enable_color_points`) and DriftCompensation / CompensationText
  (`enable_drift_compensation`).
* ZCL data types (ZCL8 §2.6.2): semi-precision floats convert both ways
  (`types::{semi_to_f32, f32_to_semi}`, `Value::as_f64`) and take part
  in reportable-change comparisons; composite values iterate their
  elements (`Value::elements`) and are built with `write_array` /
  `write_struct`.
* Manufacturer-specific clusters (ZCL8 §2.3.3):
  `ClusterInstance::manufacturer_specific(code)` registers a cluster
  that only frames carrying its manufacturer code reach (UNSUPPORTED_CLUSTER
  without a code, UNSUP_MANUF_GENERAL / CLUSTER_COMMAND with another);
  inside it the code names the cluster rather than manufacturer-specific
  attributes.
* The inter-PAN data service (R23.2 Annex G): `Stack::inter_pan_request`
  sends application frames to a broadcast, device, network-address or
  group target on any PAN, optionally secured with the shared link key,
  and received inter-PAN frames of any cluster but Touchlink
  Commissioning arrive as `StackEvent::InterPanData`
  (`panweave-runtime::interpan`).
* Fragmentation discovery and caching (R23.2 §2.2.8.4.5.1):
  `panweave-runtime::fragment_cache` — an ASDU that must be fragmented
  to a unicast peer whose parameters are unknown is held while the
  peer's Node Descriptor (with the R23 Fragmentation Parameters TLV) is
  fetched; `apsFragmentationCacheTable` keeps the answers
  (`Stack::fragmentation_entry`, `cache_fragmentation`), a peer that
  cannot take the message is reported as `StackEvent::FragmentationRefused`,
  and `Aps::single_frame_capacity` tells what fits one frame.
* Frequency agility (R23.2 Annex E): `panweave-runtime::agility` — a
  router or coordinator whose unicast failure rate passes
  `StackConfig::interference` runs an energy scan and, when its channel
  is noisier than the quietest alternative, sends
  Mgmt_NWK_Unsolicited_Enhanced_Update_notify to the network manager
  (four an hour at most, counters restarted; `StackEvent::InterferenceReported`);
  the manager receives `StackEvent::InterferenceReport` and
  `Stack::change_network_channel` broadcasts the channel change
  (nwkUpdateId incremented, the manager switching after
  nwkNetworkBroadcastDeliveryTime, apsChannelTimer holding further
  changes back). The simulator reports `Simulator::channel_energy` per
  channel.
* Mgmt_NWK_Enhanced_Update_req over multi-page channel lists follows
  §2.4.3.3.9.2 with the single 2.4 GHz interface (one channel across
  the pages for a change, the whole list into `apsChannelMaskList` —
  now with `Aib::channel_mask_pages` — for an attribute change, single
  page for an energy scan; the configuration bitmask no longer affects
  energy scans) and Mgmt_NWK_Beacon_Survey_req runs an enhanced active
  scan when asked (`Nwk::network_discovery_with`).
* The Table 2-24 startup AIB attributes are kept: `apsDesignatedCoordinator`
  and `apsChannelMaskList` come from the configuration,
  `apsUseExtendedPANID` is learnt when a network is formed or joined
  and steers later joins, and all four are stored in the AIB record
  (format 2) and restored on warm start (R23.2 §2.2.5).
* Electrical Measurement completion (ZCL8 §4.9.2.2.4–11): the RMS
  current / active power extremes, the voltage quality attributes and
  the full ACAlarmsMask (reactive power overload, average / extreme
  over and under voltage, sag and swell with the counters), the AC
  non-phase-specific set (frequency extremes, neutral current,
  polyphase totals, current harmonics with their formatting) and the
  phase B / C sets through `Phase` / `phase_attr` (`enable_phase`,
  `set_ac_phase`, `enable_ac_totals`, `set_ac_totals`, `set_harmonics`).
* Thermostat completion (ZCL8 §6.3.2.2.3–5, §6.3.2.3.5): the setpoint
  change tracking set (source / amount / UTC stamp from the endpoint's
  Time server, occupied / unoccupied setbacks clamped into their
  bounds, EmergencyHeatDelta in the running mode), the AC information
  set with `TemperatureSetpointHoldDuration`,
  `ThermostatProgrammingOperationMode` and `ThermostatRunningState`,
  and the relay status log with Get Relay Status Log / Response.
* Door Lock completion (ZCL8 §7.3): week day, year day and holiday
  schedules (Set / Get / Clear with their responses; schedule users
  gated at RF operations against the endpoint clock with the
  invalid-schedule events, holidays switching `OperatingMode` from the
  dispatcher tick), RFID codes sharing the user table (Set / Get /
  Clear / Clear All with the RFID programming events; a user keeps its
  other code when one is cleared), the event log with Get Log Record /
  Response under `EnableLogging`, the `SecurityLevel` APS policy
  enforced by the dispatcher (NOT_AUTHORIZED without APS security) and
  the counts / lengths / logging / security attributes instantiated.
* Level Control for Lighting and Pulse Width Modulation (ZCL8 §3.19,
  §3.20, §3.10.2.3.5): `level::lighting_server` (1…254),
  `enable_frequency` with `CurrentFrequency` / `MinFrequency` /
  `MaxFrequency` and Move to Closest Frequency (`ZclEvent::Frequency`),
  `pwm_server` for cluster 0x001c driven by the same engine
  (`ZclEvent::DutyCycle`), and the CoupleColorTempToLevel option: the
  dispatcher moves `ColorTemperatureMireds` with the level in colour
  temperature mode (§5.2.2.1.1).
* `panweave-zcl::clusters::io`: the Analog / Binary / Multistate
  Input, Output and Value clusters (ZCL8 §3.14) over one attribute set
  with the §3.14.11 rules (inputs writable out of service only,
  StatusFlags derived from Reliability and OutOfService, multistate and
  analog range checks, reported PresentValue / StatusFlags);
  `ClusterInstance::after_write` lets a cluster refresh derived
  attributes after a network write.
* `panweave-zcl::clusters::measurement::{scalar, concentration}`: the
  Electrical Conductivity, pH and Wind Speed clusters (ZCL8 §4.10–4.12)
  and the Concentration Measurement clusters 0x040c–0x0429 (§4.13,
  single-precision fractions); reportable changes of single / double
  precision attributes are floating-point magnitudes
  (`attribute::float_change`) in Configure Reporting, Read Reporting
  Configuration and the change detection.
* `panweave-zcl::clusters::configuration`: Device Temperature
  Configuration (§3.4, threshold dwell timers raising through the
  Alarms server), On/Off Switch Configuration (§3.9), Ballast
  Configuration (§5.3, level rules, dimming curve, lamp burn-hours
  alarm), Pump Configuration and Control (§6.2, effective modes per
  Figure 6-3, status bits, Table 6-9 alarms), Dehumidification Control
  (§6.5, demand from setpoint and hysteresis), Thermostat User
  Interface Configuration (§6.6), Shade Configuration (§7.2) and
  Barrier Control (§7.5, Go To Percent / Stop executed by the
  dispatcher as `ZclEvent::Barrier`, event counters, safety alarms,
  scene field); the facade instantiates them and the measurement
  clusters for every device type, adding Dimmable Ballast and On/Off
  Sensor builders.
* Thermostat weekly setpoint schedule (ZCL8 §6.3.2.2.3, §6.3.2.3.2–4):
  `thermostat::enable_weekly_schedule` adds `StartOfWeek`, the
  transition capacities and `TemperatureSetpointHold`; Set / Get /
  Clear Weekly Schedule are executed by the dispatcher
  (`ZclEvent::WeeklyScheduleChanged`, Get Weekly Schedule Response) and
  the schedule runs against the endpoint's Time server, applying
  transitions as `ZclEvent::Setpoints` (ADR-0015); the facade
  `thermostat_device` carries it.
* `panweave-zcl::clusters::window_covering`: the Window Covering
  cluster — information / settings attributes, per-axis open- or
  closed-loop control, the seven motion commands validated against the
  installed limits and the `Mode` maintenance bit, percentages reported
  by default, the scene extension recalled as a timed go-to, and
  `ZclEvent::WindowCovering` handing the accepted command to the
  application; facade `window_covering_device` endpoint.
* `panweave-zcl::clusters::door_lock`: the Door Lock core — the
  information, operational, security and event-mask attributes; Lock /
  Unlock / Toggle / Unlock with Timeout with the operating-mode,
  actuator, PIN, wrong-code lockout (tamper alarm) and auto-relock
  rules; a bounded PIN user table with Set / Get / Clear PIN Code,
  Clear All and user status / type commands; Operation and Programming
  Event Notifications gated by their masks with PINs masked unless
  `SendPINOverTheAir`; the scene extension as a delayed operation;
  `ZclEvent::DoorLock`, `Zcl::{set_lock_state,
  door_lock_operation_event, door_lock_programming_event}` and the
  facade `door_lock_device` endpoint. PIN codes are redacted from
  `Debug` and compared in constant time.
* `panweave-zcl::clusters::ias_ace` and `ias_wd`: the IAS ACE server
  (bounded zone table, panel status, bypass list; Get Zone ID Map /
  Zone Information / Panel Status / Bypassed Zone List / Zone Status
  answered by the dispatcher, Arm and Bypass validated against the
  arm / disarm code, Arm / Emergency / Fire / Panic handed over as
  `ZclEvent::Ace`, Zone Status Changed and Panel Status Changed for the
  bound clients, a CIE's IAS Zone client relaying notifications into
  its panel) and the IAS WD server (`MaxDuration`, Start Warning
  clamped and timed, Squawk, `ZclEvent::Warning` / `Squawk`); facade
  `ias_cie` and `ias_warning_device` endpoints.
* `panweave-zcl::clusters::electrical_measurement`: `MeasurementType`,
  the DC and single-phase AC sets with their multiplier / divisor
  attributes, min / max tracking, overload alarm masks and thresholds
  (`set_dc` / `set_ac` return the alarm codes to raise), and the profile
  command codecs; the facade instantiates it for device types that list
  it.
* `panweave-zcl::structured`: Read / Write Attributes Structured —
  selectors, element lookup in arrays and structures (index 0 = count),
  element replacement, set / bag add and remove, the Write Attributes
  Structured Response with the failing selector — executed by every
  cluster instance, with client codecs in `global`.
* `panweave-zcl::clusters::commissioning`: the Commissioning cluster —
  the startup attribute set with the join, end-device and concentrator
  parameters (keys write-only and redacted), the Table 13-5
  consistency check behind Restart Device (`ZclEvent::Restart`), Save /
  Restore / Reset Startup Parameters over a bounded store — plus
  `Stack::{startup_set, seed_startup_set, restart_from_startup_set}`
  applying a set by forming, silently adopting, rejoining or
  associating once the leave completes.
* Commissioning cluster completion (ZCL8 §13.2.2.3): the saved startup
  sets live in non-volatile storage (`Kind::StartupSets`, stored on
  Save / Reset with `StackEvent::StartupSetsChanged`, restored by
  `Stack::restore`), Restart Device is carried out by the stack after
  the delay plus RAND(jitter × 80 ms), and an applied set's join,
  end-device and concentrator parameters become the stack's ZDO
  configuration attributes, poll rate and concentrator settings.
* `Access::SECRET`: credential attributes answer NOT_AUTHORIZED to reads
  and are redacted from `Attribute`'s `Debug` output (as are all
  key128 attributes).
* Touchlink commissioning (BDB 3.1 §12, ZCL8 §13.3):
  `panweave-security::touchlink` (network key transport with the
  development, master and certification algorithms, §13.3.4.11 test
  vectors; `BlockCipher::decrypt_block`), `panweave-zcl::clusters::touchlink`
  (all inter-PAN and utility command codecs), `panweave-aps::interpan`
  (stub NWK and inter-PAN APS headers), `panweave-bdb::touchlink`
  (initiator and target machines: channel scans, candidate selection,
  device information and identify, address / group / free-range
  assignment, network start and join, network update, touchlink reset,
  stealing policy) and the runtime integration (`Stack::{enable_touchlink,
  touchlink_start, touchlink_select, touchlink_identify,
  touchlink_device_information}`, `StackEvent::Touchlink`, inter-PAN
  transmission through `MacService::data_request_inter_pan`, distributed
  network formation / adoption / rejoin from the exchanged parameters).
* `panweave-smart-energy::clusters::tunneling`: the Tunneling cluster
  codecs and a server-side tunnel table (identifier allocation, peer
  binding, transfer-size and `CloseTunnelTimeout` enforcement, flow
  control windows, closure notifications, supported-protocol paging).
* `panweave-smart-energy::clusters::prepayment`: the Prepayment cluster
  attribute identifiers and bitmaps, every client and server command
  codec of D.7, and an `Account` applying the top-up limits, emergency
  credit selection, credit status derivation, debt changes and
  collections with the top-up and debt logs.
* `panweave-smart-energy::clusters::calendar`: the Calendar cluster
  codecs (PublishCalendar, fragmented PublishDayProfile / PublishSeasons
  / PublishSpecialDays, PublishWeekProfile, CancelCalendar and the Get*
  requests) and a bounded client `Store` keeping one calendar per type
  with the newer-replaces / cancellation rules and day-profile lookup by
  date through special days, seasons and week profiles.
* `panweave-smart-energy::clusters::events`: the Events cluster codecs
  (PublishEvent, GetEventLog, PublishEventLog, ClearEventLog request and
  response) and a bounded server `Log` with most-recent-first filtering
  by log, event id and time window, offset paging split across commands
  and per-log clear permissions.
* `panweave-smart-energy::clusters::energy_management`: the provisional
  Energy Management cluster — attribute definitions, the ManageEvent
  codec and a `Server` next to the DRLC scheduler applying the opt-out /
  opt-in / duty-cycling rules of D.12.2.4.1 (mandatory events refuse
  opt-out with Invalid Opt-out, unknown events answer Event Not Found),
  the derived `LoadControlState` / `CurrentEventID` /
  `CurrentEventStatus` values, the Conformance Level rule and the
  DutyOnTime / DutyOffTime algorithm. `drlc::EventStatus` gained the
  `InvalidOptOut` (0xF6) and `EventNotFound` (0xF7) values.
* `panweave-smart-energy::clusters::mdu_pairing`: the provisional MDU
  Pairing cluster — PairingRequest / PairingResponse codecs, a server
  `respond` fragmenting the virtual-HAN list (WAIT_FOR_DATA on a version
  match or missing data) and a client `Assembler` collecting fragments
  into a `VirtualHan` before it restricts discovery and binding.
* `panweave-smart-energy::clusters::sub_ghz`: the Sub-GHz cluster —
  page 28–31 channel mask attributes with helpers, the Suspend ZCL
  Messages / Get Suspend ZCL Messages Status codecs and a client
  `Suspension` holding ZCL traffic for the announced period.
* `panweave-smart-energy::clusters::device_management`: the Device
  Management cluster — supplier / tenancy / backhaul / HAN attribute
  identifiers, the change-control and event-configuration bitmaps,
  codecs for every command (change of tenancy and supplier, password
  delivery with a redacted constant-time `Password`, Site ID and CIN
  updates, event configuration set / get / report with the four "apply
  by" selectors), a client `EventConfig` table with fragmented reports
  and a client `Pending` store applying the implementation-time,
  cancellation (0xFFFFFFFF) and provider-match rules.
* `panweave-smart-energy::clusters::drlc::Scheduler` follows the Annex E
  overlapping-event rules: a start in the past runs from now with the
  original end kept, a superseded running event holds its state until
  the successor's effective start, successive events with randomization
  are never reported superseded and leave no artificial gap, and an
  event for a subset of the device classes supersedes only when it
  covers every class of the previous event this device has.
* `panweave-aps::interpan`: the stub APS header now carries the
  Security, ACK Request (APS counter) and Extended Header (fragment)
  bits; `secure` / `unsecure` protect an inter-PAN frame with the
  partner's APS link key. Group delivery is encoded as 0b11 per R23.2
  §G.3.3 (it was 0b01).
* `panweave-smart-energy::interpan`: the Annex B enhanced inter-PAN
  policy — every cluster secured except Key Establishment, the
  reception filter dropping non-conforming frames, and the B.6 channel
  survey list picking the strongest receiver (ADR-0013).
* `panweave-smart-energy::security`: the §5.4 profile security policies
  as pure objects — the permit-join broadcast schedule, the autonomous
  scan back-off, a Trust Center `Registry` (install-code provisioning,
  registration status, preconfigured / CBKE / stale key states with the
  §5.4.6–§5.4.7 verdicts for incoming and outgoing frames, the
  20-minute CBKE deadline, leave keeps the key, Table 5-10 backup and
  restore), the Table 5-11 link key hash, the joiner's reaction to a
  Key Establishment result, partner-key brokering rules and the
  device-side Trust Center swap-out state machine.
* `panweave-smart-energy::commissioning`: the §5.5.5 life-cycle state
  machine — auto-join scan schedule, wrong-PAN back-out limits, Key
  Establishment pacing without leaving, the leave-instruction rules,
  rediscovery periods, the 24-hour keep-alive failure limit and the
  rejoin-and-recovery procedure with its hourly slow-down.
* `panweave-smart-energy::endpoints` and the facade's
  `smart_energy_endpoints` (feature `smart-energy`): server and client
  instances of every Smart Energy cluster with their mandatory
  attributes, and builders for the ten Table 5-13 devices on profile
  0x0109 with the Table 6-1 common clusters, checked against the
  device's cluster rules.
* `panweave-zcl::layer::Zcl::set_link_key_policy`: a per-profile
  predicate naming the clusters whose frames must arrive APS link-key
  secured; unsecured frames of those clusters are answered with a
  Default Response FAILURE under the network key and dropped (the
  FAILURE itself is exempt). `panweave-smart-energy::zcl_link_key_policy`
  supplies the Table 5-12 rule.
* `panweave-smart-energy::profile::PRESET` and the facade's
  `smart_energy_endpoints::{apply_profile, apply_profile_to_stack}`:
  the §5.3 stack profile values (join scans, rejoin intervals, poll
  rate, APS inter-frame delay, maximum incoming transfer size,
  concentrator radius) applied to a stack configuration.
* `panweave-smart-energy::clusters::drlc::EventStore`: the ESI's store
  of issued Load Control Events answering Get Scheduled Events with the
  D.2.3.3.2.3 filters and orderings; `report_delay_ms` draws the 0–5 s
  Report Event Status delay.
* `panweave-smart-energy::clusters::messaging::Server`: the ESI's
  message store answering Get Last Message, gathering Message
  Confirmations and holding a pending Cancel All Messages for
  GetMessageCancellation; `ImplementationTime` codec.
* `panweave-smart-energy::clusters::price::extended`: every optional
  Price command of Tables D-95 / D-96 (block periods, conversion factor,
  calorific value, tariff information, fragmented price matrix and block
  thresholds, CO2, tier labels, billing periods, consolidated bills, CPP
  events, credit payments, currency conversion, cancel tariff and the
  Get* requests), a generic `Scheduled` current-and-next store with the
  cancellation and ordering rules, and a client `TariffStore` assembling
  tariffs with price and block lookup; `price::FULL_SERVER_DEF` /
  `FULL_CLIENT_DEF` declare the full command set.
* `panweave-smart-energy::clusters::metering::extended`: every other
  Metering command of Tables D-47 / D-63 (mirroring, fast poll,
  snapshots with TOU sub-payloads, sampling, notification schemes and
  flags, supply control) with `FastPoll`, `Sampler`, `Snapshots` /
  `SnapshotAssembler`, `SupplyControl` and `MirrorTable` state helpers;
  `metering::FULL_SERVER_DEF` / `FULL_CLIENT_DEF`.
* `panweave-smart-energy::clusters::prepayment::Pending`: the scheduler
  of the timed prepayment commands (immediate / delayed / 0xFFFFFFFF
  cancellation, newer replaces older, applied on poll), with
  `Timed::apply` covering Change Payment Mode and Set Overall Debt Cap
  on the `Account`.
* `panweave-zdo`: Mgmt_NWK_Enhanced_Update_req / _notify,
  Mgmt_NWK_IEEE_Joining_List_req / _rsp (answered from the NWK joining
  policy and list, applied on receipt, broadcast by
  `Zdo::broadcast_joining_list`), Mgmt_NWK_Unsolicited_Enhanced_Update_notify
  and Mgmt_NWK_Beacon_Survey_req / _rsp codecs and server processing;
  `panweave-nwk::joining_list` holds `mibJoiningPolicy` /
  `mibJoiningIeeeList` and gates association and initial commissioning
  joins; the runtime runs beacon surveys (`StackEvent::JoiningListUpdated`).
* Application link keys (R23.2 §4.7.3.9, BDB 3.1 §7.4):
  `Stack::request_application_link_key`, Trust Center brokering under
  `allowApplicationKeyRequests` and the `applicationKeyRequestList`,
  `StackEvent::ApplicationLinkKey` on both devices; data frames under an
  application link key carry the extended nonce and the NWK records the
  originator of a single-hop secured frame in the address map.
* `panweave-bdb::setup_code`: short device setup codes (BDB 3.1
  §6.12) — the modified base32 alphabet, decoding to the padded pass
  code used by SPEKE, and display encoding.
* Trust Center swap-out (R23.2 §4.7.4): `Stack::trust_center_backup`
  (the device key-pair set with the AES-MMO hashed
  `TrustCenterSwapOutLinkKey`, never the live key) and
  `Stack::restore_trust_center_backup` on a replacement Trust Center;
  on the node, an APS command that fails during a Trust Center rejoin is
  retried under the hashed key (`ApsSecurity::unsecure_swap_out`), the
  entry moves to the new Trust Center, `StackEvent::TrustCenterSwapped`
  is reported and the link key is renewed before APS-secured messaging.
  A rejoin also drops a stale neighbour that held the new parent's short
  address, and an unsecured Rejoin / Commissioning Response to an
  unsecured rejoin started from an operating network is accepted.
* Power negotiation (R23.2 §3.6.11, §3.4.13, Annex D.11.2), behind
  `NwkConfig::power_control`: periodic Link Power Delta notifications
  from routers, notifications / requests from end devices with the
  parent's responses, `nwkLinkPowerDeltaTransmitRate` and the parent
  information bit, and the MAC's Power Control Information Table
  (`panweave_mac::power`, `MacServiceConfig::power_limits`) that sets
  the transmit power of every unicast to a negotiated link;
  `StackEvent::LinkPowerDelta` reports processed commands.
* Enhanced beaconing (R23.2 Annex D.11.1): `panweave_mac::ie` with the
  payload IE list, the EB Filter IE and the Zigbee Payload IE (Rejoin,
  TX Power and EB Payload sub-IEs); `MacService::scan_enhanced` sends
  Enhanced Beacon Requests and, behind `MacServiceConfig::enhanced_beacons`,
  routers answer them per the filter, the mirrored `mibJoiningPolicy` /
  `mibJoiningIeeeList` (`Stack::sync_joining_filter`) and the extended
  PAN ID of a rejoin with Enhanced Beacons presented to the NWK as
  standard beacons; `NwkConfig::enhanced_beacon_requests` makes network
  discovery use them. The TX Power IE exchange seeds the Power Control
  Information Table (D.11.2.4.2).
* Network key update (R23.2 §4.6.3.4): `Stack::update_network_key` on
  the Trust Center (alternate key broadcast, unicast to rx-off
  children, Switch Key after `nwkNetworkBroadcastDeliveryTime`);
  routers unicast a received broadcast network key to their rx-off
  children (§4.4.2.3); `StackEvent::NetworkKeySwitched` names the
  retired sequence number; a sleepy end device follows its parent onto
  the alternate key (ADR-0014).
* Zigbee Direct network key rotation (ZD 1.1 §9):
  `panweave_direct::rotation` with the past-network-key store (kept by
  the facade's `DirectState`, persisted under `Kind::DirectPastKeys`
  and restored by `Node::initialize`), the Limited Authorization
  `SessionClass` and the Transport Key forwarding decision; the session
  responder hands the ZVD's key sequence number to the secret resolver
  and reports it in `Established::peer_key_sequence`.
* `panweave-nwk::interface`: the MAC Interface Table (R23.2 Table 3-69)
  with NLME-SET-INTERFACE / NLME-GET-INTERFACE semantics
  (`Nwk::interfaces`): scans and formation are confined to the channels
  an enabled interface supports, the entry records the channel in use,
  counts unicast traffic and its `RoutersAllowed` gates router joins.
* Source routing origination (R23.2 §3.6.4.3.1): a concentrator with a
  stored route record sends its frames source routed; a Route Record
  precedes an originator's own data to a concentrator without a route
  cache (§3.6.4.5.5). After an address conflict re-addressing the
  device announces itself and reports `StackEvent::AddressChanged`.
* `Stack::remove_node` (BDB 3.1 §13.4 / §13.5): Mgmt_Leave_req on a
  distributed network, Remove Device to a router itself or through an
  end device's parent on a centralized one. A router of a distributed
  network now installs the joiner's entry under the distributed global
  link key before handing out the network key.
* On-Network TCLK Update procedure (BDB 3.1 §10.2.4): after a join
  with a global link key the node sends Node_Desc_req to the Trust
  Center with its key negotiation methods; below stack revision 21 the
  key stays (`StackEvent::LinkKeyUpdateSkipped`), the symmetric
  exchange runs below revision 23 or when the Zigbee 3.0 mechanism is
  selected, the selected SPEKE negotiation otherwise;
  `StackEvent::LinkKeyUpdateFailed` when the descriptor never arrives.
  The Trust Center's Node_Desc_rsp carries the Selected Key
  Negotiation Method TLV (`ZdoContext::select_key_negotiation`).
* Parent_annce after a reboot (R23.2 §2.4.3.1.12): a resumed router or
  coordinator announces its end device children after
  `apsParentAnnounceBaseTimer` plus jitter and drops the ones another
  router claims in Parent_annce_rsp (`StackEvent::ChildClaimed`).
* ZDO configuration attributes in effect (R23.2 Table 2-135): an end
  device counts parent link failures against
  `:Config_Parent_Link_Retry_Threshold` before rejoining and paces
  parent-loss rejoins by `:Config_Rejoin_Interval` (doubling up to
  `:Config_Max_Rejoin_Interval`); Bind_req beyond `:Config_Max_Bind` is
  refused with INSUFFICIENT_SPACE.
* ZCL reporting: a report spanning several Report Attributes frames
  ends each frame with `AttributeReportingStatus` (Pending / Complete,
  ZCL8 §2.3.4.5.2).
* Diagnostics cluster (ZCL8 §3.15): every attribute is instantiated
  and fed by the stack — MAC broadcast / unicast receptions and
  transmissions, retries, failures and queue overflows
  (`MacService::stats`), APS broadcast / unicast traffic, successes and
  frame counter failures, route discoveries initiated, neighbor table
  additions / removals / stale entries, join indications, children that
  moved and the average MAC retries per APS message.
* Device interview (BDB 3.1 §9.9): `TrustCenterPolicy::interview_joiners`
  holds the network key after a joiner's negotiated key is verified
  (`StackEvent::JoinerVerified`) until `Stack::admit_joiner`;
  `Stack::reject_joiner` removes the device.
* Trust Center connectivity (BDB 3.1 §7.3.3): a router whose Trust
  Center has no Keep-Alive server polls it with Node_Desc_req instead.
* `Stack::set_fast_polling` keeps a sleepy end device at its fast poll
  rate on request (BDB 3.1 §6.6); the facade polls fast while a
  commissioning procedure runs.
* `panweave-zcl::clusters::ota`: the OTA Upgrade cluster — file header
  and sub-elements, all §11.13 command codecs, a client download machine
  (notify jitter, query, block requests with waits and rate limiting,
  verify hand-off, Upgrade End, activation policy) and server helpers
  over an `ImageSource`; a simulator test downloads an image over the
  air.
* OTA upgrade server discovery (ZCL8 §11.8): `Stack::discover_ota_server`
  resolves a preprogrammed `UpgradeServerID` with NWK_addr_req or finds
  the first server answering a Match_Desc_req, stores its IEEE address
  and asks the Trust Center for an application link key when the server
  is not the Trust Center (`StackEvent::OtaServer` /
  `OtaServerNotFound`); `ota::PageService` serves an Image Page Request
  block by block at the response spacing (§11.13.7.4); the client
  machine re-sends Upgrade End Request hourly while told to wait
  indefinitely and may apply the image after three unanswered queries
  (§11.16); Query Device Specific File codecs (§11.13.10–11).
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
* `examples/esp32c6-super-mini` (`docs/esp32c6.md`): Panweave on real
  hardware — the ESP32-C6 Super Mini's 802.15.4 radio through
  `esp-radio` (`Radio` executing the stack's `MacAction`s with hardware
  acknowledgements and address filtering, the driver's PIB-at-next-frame
  behaviour bridged by a self-addressed flush frame), the TRNG as
  `CryptoRng`, the eFuse MAC as IEEE address, the on-chip flash as
  `Storage`, a `Runner` loop; firmware images for a coordinator, a
  router On/Off Light, an On/Off switch and a temperature sensor, joined
  and bound with the BOOT button; an `esp32c6` CI job builds them.
* `panweave_storage::nor_flash::NorFlashStore` (feature `nor-flash`): a
  log-structured `Storage` on any `embedded-storage` NOR flash — two
  halves of whole sectors, CRC-checked records, compaction with an
  atomic switch (the new half's header is written last), torn records
  skipped; `Kind::code` / `Kind::from_code` give record kinds a stable
  on-medium code. Tested on the host against a RAM flash with real NOR
  semantics and simulated power loss.
* `docs/footprint.md`: the ROM / RAM budget of a router on a Cortex-M4F
  with a size probe (`examples/size-probe`, a bare-metal binary linking
  the facade `Node`), `scripts/elf_size.py` to read it (totals and the
  `PANWEAVE_SIZES` component table without binutils) and a `footprint`
  CI job printing both profiles; the `small-tables` feature of
  `panweave-runtime` / `panweave` (8 clusters × 24 attributes per
  endpoint instead of 12 × 36, tested in CI) with the dimensions named
  by `ENDPOINTS`, `ENDPOINT_CLUSTERS`, `CLUSTER_ATTRIBUTES` and the
  aliases `StackEndpoint`, `StackCluster`.

### Changed

* ZCL attribute storage keeps a value of up to eight octets and its
  factory default inline in the entry and draws strings, composites and
  keys from a 384-octet pool per cluster (`ATTRIBUTE_POOL`, five wide
  attributes); an `Attribute` is 80 bytes instead of 216, a default
  router `Node` 141 KiB of RAM on a Cortex-M4F instead of 226 KiB.
  `AttributeTable` hands out `AttrRef` / `AttrMut` views (`get`,
  `get_mut`, `at`, `at_mut`, `iter`) in place of `&Attribute` /
  `&mut Attribute`; `add_reported` replaces `Attribute::new` +
  `with_default_reporting` + `add_attribute(Attribute)`, and the
  reporting state is `AttrRef::reporting: Option<&ReportState>`. The
  `Debug` output of a table lists its attributes (secrets redacted)
  rather than the raw pool.
* `panweave_smart_energy::endpoints` builders are generic over the
  attribute capacity (`server::<A>`, `metering_server::<A>`, …) so they
  follow the stack's profile.

* Client cluster instances built from a server definition answer
  Discover Commands Received / Generated for their own side
  (`ClusterDef::mirrored`); they used to list the server's commands.
* A factory reset keeps the outgoing NWK frame counter record (BDB 3.1
  §13) and `Stack::restore` reloads it even on a factory-new device; the
  touchlink Reset To Factory New clears persistent data only once the
  leave has completed; `Stack::erase_persisted` also clears the Green
  Power proxy table and Zigbee Direct past keys.
* Aliased NWK broadcasts (Green Power tunnelling, Device_annce on behalf
  of a GPD) are recorded in the broadcast transaction table under the
  alias source rather than the device's own address, so their relays
  count as passive acknowledgements instead of being relayed again and
  retried; the runtime's broadcast transaction table holds 16 records so
  a commissioning burst does not drop the broadcasts that follow it.
* Frames for sleepy children are secured when the child polls: the NWK
  registers a deferred indirect transaction
  (`NwkAction::MacDataDeferred`, `MacService::data_request_deferred`),
  the MAC answers the poll with frame pending and raises
  `MacEvent::IndirectReady`, and `Nwk::on_mac_indirect_ready` secures
  and sends the frame directly with a fresh counter. A frame held for a
  sleepy child could previously be overtaken by later transmissions the
  child overheard and be dropped as a replay. A device's own broadcast
  copies for sleepy children take the same path.
* The runtime's ZCL attribute capacity per cluster instance is 36 and
  an endpoint holds 12 cluster instances (`Zcl<2, 12, 36>`,
  `EndpointInstance<12, 36>`) so a full-capability Color Control server,
  the complete Diagnostics server and the Dimmable Ballast / On/Off
  Sensor cluster sets fit; scene extension field sets hold 32 octets.

* On/Off commands are no longer delivered to the application as
  `StackEvent::ZclCommand`: the stack applies them and reports
  `StackEvent::OnOff`; `on_off::apply` takes the current time and
  `panweave_sim::OnOffApp` mirrors the events.
