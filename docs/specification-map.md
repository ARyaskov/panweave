# Specification map

This document maps the normative inputs of Panweave onto the crates and
modules that implement them. It deliberately paraphrases; it does not
reproduce specification prose, diagrams, or tables. Section numbers refer to
the documents listed below and are the primary traceability key used in
source comments (`Spec: R23.2 §3.6.4.5`), in `conformance/*.toml`, and in
ADRs.

Panweave is an independent implementation. It is not affiliated with,
sponsored by, endorsed by, or certified by the Connectivity Standards
Alliance. Compatibility names are used descriptively only.

## Short identifiers

| Id | Document | Revision / date | Local file |
|----|----------|-----------------|------------|
| `R23.2` | Zigbee Specification (05-3474-23) | Revision 23.2, 2025-11-10 | `docs-06-3474-23-csg-zigbee-specificationR23.2_clean.pdf` |
| `ZCL8` | Zigbee Cluster Library Specification (07-5123) | Revision 8, 2019-12 | `07-5123-08-Zigbee-Cluster-Library-1.pdf` |
| `BDB3.1` | PRO Base Device Behavior Specification (22-65816-030) | v3.1, 2025-11-10 | `22-65816-030-PRO-BDB-v3.1-Specification-PRO Base Device Behavior Specification.pdf` |
| `DTL2` | Device Type Library Specification (23-02016) | Revision 2 | `23-02016-002-Device-Type-Library.pdf` |
| `GP1.1.2` | Green Power feature specification, Basic functionality set (14-0563-19) | v1.1.2 | `14-0563-19_Green-Power-Basic_specification_v1.1.2.pdf` |
| `ZD1.1` | Zigbee Direct Specification (20-27688-041) | Revision 1.1, 2024-10-16 | `20-27688-041-zigbee_direct_spec_v1.1.pdf` |
| `SE1.4a` | Zigbee Smart Energy Standard | 1.4a | `zigbee-smart-energy-1.4a-specification.pdf` |

The PDFs are not stored in this repository. `specification/README.md`
explains how to obtain them and how the extracted text is used during
development.

## R23.2 — Zigbee Specification

Dependencies: IEEE 802.15.4-2015 (MAC/PHY), ZCL8 (for ZDO/ZDP commissioning
clusters referenced by BDB), BDB3.1 (device behaviour on top of the stack).

### Major subsystems and owning crates

| Chapter / area | Content (paraphrased) | Owning crate / module |
|---|---|---|
| §1.2.5, §1.2.6, Annex I | Malformed-frame handling rules, TLV encoding rules, global TLV registry (IDs 64–76) | `panweave-codec::tlv`, `panweave-types::tlv` |
| §2.2 APS | APS data/management services, frame formats (§2.2.5), command frames (§2.2.6), constants/AIB (§2.2.7), functional description incl. ack, retry, fragmentation, duplicate rejection, binding, groups (§2.2.8) | `panweave-aps` |
| §2.3 Application framework | Profiles, descriptors (node/power/simple/complex), endpoint model, PAN-ID conflict application behaviour | `panweave-zdo::descriptors`, `panweave-runtime::endpoint` |
| §2.4 ZDP | Device/service discovery (§2.4.3.1), bind management (§2.4.3.2), network management (§2.4.3.3), security client services (§2.4.3.4) and their server counterparts (§2.4.4), enumeration and status values (§2.4.5, §2.4.6) | `panweave-zdo` |
| §2.5 ZDO | Device object roles, TC/NM/BM/SM objects, configuration attributes | `panweave-zdo::objects`, `panweave-runtime` |
| §3.2 NWK services | NLDE/NLME primitives | `panweave-nwk::service` |
| §3.3 NWK frame formats | General NPDU header, data and command frames, source-route subframe | `panweave-nwk::frame` |
| §3.4 NWK commands | Route request/reply, network status, leave, route record, rejoin request/response, link status, network report/update, end-device timeout request/response, link power delta, network commissioning request/response | `panweave-nwk::command` |
| §3.5 Constants / NIB | NWK constants and information base | `panweave-nwk::nib` |
| §3.6.1 Network and device maintenance | Discovery, formation, permit joining, join (association, rejoin, direct), leave, address assignment, address conflicts, neighbor tables, PAN-ID conflict resolution | `panweave-nwk::{discovery, formation, join, leave, neighbor, addressing, conflict}` |
| §3.6.2 Transmission and reception | Header construction, radius handling, sequence numbers, retransmission, end-device initiator handling | `panweave-nwk::tx`, `panweave-nwk::rx` |
| §3.6.3 LQI in neighbor entries | Link cost estimation | `panweave-nwk::neighbor::cost` |
| §3.6.4 Routing | Routing table, route discovery table, route request/reply processing, many-to-one, source routing, route record, route maintenance, network status handling | `panweave-nwk::routing` |
| §3.6.5–§3.6.8 | Beacon scheduling (non-beacon networks only), broadcast (BTT, passive ack), multicast (deprecated in R23), beacon payload | `panweave-nwk::{broadcast, beacon}` |
| §3.6.9 Persistent data | Which NIB elements survive reset | `panweave-storage` |
| §3.6.10 End-device aging | Timeout request/response, keep-alive methods, parent-side aging | `panweave-nwk::child` |
| §3.6.11 Power negotiation | Link power delta | `panweave-nwk::power` |
| §3.6.12 Multiple MAC interfaces | Interface table | `panweave-nwk::interface` |
| §4.2–§4.3 NWK security | Auxiliary header, CCM* secured NPDU, security-related NIB, frame counter rules (§4.3.4) | `panweave-security::nwk` |
| §4.4 APS security | Transport key, update device, remove device, request key, switch key, verify key, confirm key, key negotiation (DLK), secured APDU, security AIB | `panweave-security::aps`, `panweave-aps::security_commands` |
| §4.5 Common elements | Auxiliary frame header, security parameters, key hierarchy (hashed keys, key-load / key-transport keys) | `panweave-security::{aux_header, key_hierarchy}` |
| §4.6 Functional description | Security initialisation, Trust Center application, joining/authentication procedures, key update/switch, device leaving | `panweave-security::procedures`, `panweave-bdb` |
| §4.7 Centralized networks | Trust Center policies (§4.7.1), TC link keys, policy values (§4.7.3), TC swap-out (§4.7.4) | `panweave-security::trust_center` |
| §4.8 Distributed networks | Distributed TC address, network key updates, link keys | `panweave-security::distributed` |
| §4.9 Device operations | Joining device policies, TC address handling, receiving/negotiating link keys, passphrase update | `panweave-security::device` |
| Annex A, B, C | CCM*, AES-MMO hash, keyed hash (HMAC-AES-MMO), test vectors | `panweave-security::{ccm, mmo, kdf}` |
| Annex D | MAC/PHY clarifications: status codes, association usage, frame version, beacon payload, backoff timing, enhanced beacons, power control, sub-GHz PHYs | `panweave-mac` (traits) / `panweave-nwk::beacon` |
| Annex E, F | Network manager / frequency agility guidance | `panweave-nwk::network_manager` |
| Annex G | Inter-PAN transmission (stub NWK header, inter-PAN APS) | `panweave-aps::interpan` |
| Annex H | GP device frame test vectors | `panweave-green-power` tests |
| Annex J | ECDHE/SPEKE over Curve25519 | `panweave-security::dlk` |
| Annex K | Provisional features (routing improvements, extended route info TLVs) | tracked as `not-implemented` |

### State machines identified

* Network discovery / formation (§3.6.1.1–§3.6.1.3).
* Join (association), rejoin (secured/unsecured/TC), direct join, orphan
  handling (§3.6.1.4).
* Leave initiated locally vs. remotely, with rejoin/remove-children flags
  (§3.6.1.10).
* Route discovery table lifecycle and routing table entry states
  (`ACTIVE`, `DISCOVERY_UNDERWAY`, `DISCOVERY_FAILED`, `INACTIVE`,
  `VALIDATION_UNDERWAY`) (§3.6.4).
* Broadcast transaction table entries and passive acknowledgement (§3.6.6).
* End-device timeout / keep-alive (§3.6.10).
* Trust Center join authorisation: pre-authorised, authorising (key
  transport), authenticated (link-key verification), interview (R23) (§4.6,
  §4.7).
* Key negotiation (DLK) protocol exchange (§4.4.9, Annex J).
* Network key update / switch with sequence numbers (§4.6.3).
* Frame-counter windows and persistence (§4.3.4).

### Wire-format families

NPDU header, NWK command payloads, APS header (data/command/ack), APS
command payloads, auxiliary security header, ZDP request/response payloads,
descriptors, TLVs (local and global), beacon payload, inter-PAN stub header.

### Security-sensitive areas

Everything in chapter 4; also the address-map / neighbor-table consistency
checks (§3.3.1.6), frame-counter persistence (§4.3.4), TC policy enforcement
(§4.7.1), key derivation and hashing (Annex B), DLK (§4.4.9, Annex J), device
interview (§2.4.3.4, BDB §9.9), and the malformed-frame rules (§1.2.5).

### Persistent state

NIB elements listed in §3.6.9 (extended PAN ID, PAN ID, channel, short
address, network key material and sequence numbers, outgoing frame counters,
neighbor/child information needed to rejoin, address map, TC address, etc.),
APS binding and group tables, security material set (§4.4.12), TC link key
and passphrase material, join/interview state.

## ZCL8 — Cluster Library

Dependencies: R23.2 (APS transport, endpoints), DTL2 (device composition).

| Chapter | Content | Owning module |
|---|---|---|
| 2 Foundation | Cluster/attribute/command model, data types (§2.6), frame formats (§2.4), general commands (§2.5): read/write attributes, configure/read reporting, report attributes, default response, discover attributes/commands, read/write structured | `panweave-zcl::{frame, types, global}` |
| 3 General | Basic, Power Configuration, Device Temperature, Identify, Groups, Scenes, On/Off, On/Off Switch Configuration, Level, Alarms, Time, RSSI Location, Diagnostics, Poll Control, Power Profile, Pulse Width Modulation | `panweave-zcl::clusters::general` |
| 4 Measurement & Sensing | Illuminance, Illuminance Level, Temperature, Pressure, Flow, Water Content, Occupancy, Electrical, Conductivity, Wind Speed, Concentration | `panweave-zcl::clusters::measurement` |
| 5 Lighting | Color Control, Ballast Configuration | `panweave-zcl::clusters::lighting` |
| 6 HVAC | Pump, Thermostat, Fan Control, Dehumidification, Thermostat UI | `panweave-zcl::clusters::hvac` |
| 7 Closures | Shade Configuration, Door Lock, Window Covering, Barrier Control | `panweave-zcl::clusters::closures` |
| 8 Security & Safety | IAS Zone, IAS ACE, IAS WD | `panweave-zcl::clusters::ias` |
| 9 Protocol Interfaces | Generic Tunnel, BACnet Tunnel, Partition | `panweave-zcl::clusters::protocol` |
| 10 Smart Energy | Price, DRLC, Metering, Messaging, Tunneling, Key Establishment, Meter Identification | `panweave-smart-energy` |
| 11 OTA Upgrade | OTA cluster, file format, upgrade process | `panweave-zcl::clusters::ota` |
| 12 Telecommunications | Information, Voice over Zigbee | tracked `not-implemented` |
| 13 Commissioning | Commissioning cluster, Touchlink commissioning | `panweave-zcl::clusters::commissioning`, `panweave-bdb::touchlink` |
| 14 Retail | Mobile device configuration, neighbor cleaning, nearest gateway | tracked `not-implemented` |
| 15 Appliances | Appliance statistics | tracked `not-implemented` |

State machines: attribute reporting timers (§2.5.7 / §2.5.11), Level
Control transitions (§3.10), Scenes transition, Identify time, Poll Control
check-in, OTA upgrade process (§11.16), Color Control transitions and loops
(§5.2), Door Lock states, Window Covering movement, IAS Zone enrolment
(§8.2.2.2.3).

Security-sensitive: Key Establishment (chapter 10, also SE Annex C), OTA
image signature verification (§11.6), Door Lock PIN handling (§7.3).

## BDB3.1 — Base Device Behavior

Dependencies: R23.2 (stack), ZCL8 (Identify, Groups, commissioning clusters,
Touchlink), DTL2.

| Chapter | Content | Owning module |
|---|---|---|
| 5 | Constants, configuration attributes (`bdbNodeIsOnANetwork`, commissioning mode/status, channel masks, TC link key exchange settings, join policy) | `panweave-bdb::config` |
| 6 | Logical device types, security models (centralized vs distributed), commissioning overview, minimum requirements, default reporting, MAC polling, persistent data, install codes, short setup codes | `panweave-bdb::policy` |
| 7 | Initialisation, on-network TCLK update, TC connectivity (keep-alive, poll control, node descriptor), application link keys | `panweave-bdb::init`, `panweave-bdb::tclk` |
| 8 | Network formation | `panweave-bdb::formation` |
| 9 | Network discovery, symmetric key exchange, key negotiation join, certificate-based TCLK exchange, on/off-network steering, device interview | `panweave-bdb::steering`, `panweave-bdb::interview` |
| 10 | Rejoin procedure | `panweave-bdb::rejoin` |
| 11 | Finding & binding (initiator/target) | `panweave-bdb::finding_binding` |
| 12 | Touchlink initiator/target | `panweave-bdb::touchlink` |
| 13 | Reset procedures (basic cluster, touchlink, local action), node removal | `panweave-bdb::reset` |

State machines: top-level commissioning mode sequencing, network steering
(on/off network), formation, finding & binding, touchlink, TCLK update, rejoin
back-off, device interview.

## DTL2 — Device Type Library

Dependencies: ZCL8 cluster definitions; R23.2 simple descriptors.

Chapters 4–~40 define individual device types, each with a device ID,
mandatory/optional server and client clusters, restrictions, and PICS
expectations. Owning crate: `panweave-device-library`, expressed as
Panweave-maintained metadata (`device-types.toml`) from which builders and
validators are generated.

## GP1.1.2 — Green Power Basic

Dependencies: R23.2 (Annex G inter-PAN stub NWK header, Annex H test vectors),
ZCL8 (Green Power cluster 0x0021).

| Area | Content | Owning module |
|---|---|---|
| A.1.4–A.1.5 | GPDF frame format, frame types, GP stub processing, security operation (key derivation, TC-LK protection), test vectors | `panweave-green-power::{gpdf, security}` |
| A.1.6–A.1.7 | GPD addressing (SrcID / IEEE+endpoint), bidirectional operation, security parameters, GPD implementation notes | `panweave-green-power::gpdf::GpdId` |
| A.3.2–A.3.4 | Infrastructure device roles (proxy basic, combo basic, commissioning tool), GP cluster server/client attributes and commands | `panweave-green-power::cluster` |
| A.3.5–A.3.9 | Proxy/sink operation, proxy and sink tables, tunnelling (GP Notification, Commissioning Notification, Pairing, Proxy Commissioning Mode, Response), security handling, commissioning procedure | `panweave-green-power::{proxy, proxy_table}` (sink: planned) |
| A.4 | GPD command IDs and payloads | `panweave-green-power::command` |

State machines: proxy commissioning mode, sink commissioning (with/without
bidirectional exchange), duplicate filtering windows, security frame-counter
handling per GPD.

## ZD1.1 — Zigbee Direct

Dependencies: R23.2 (Trusted link, TLVs, DLK, network commissioning request),
BLE core (GATT) — abstracted in Panweave.

| Chapter | Content | Owning module |
|---|---|---|
| 6 | Security model, session establishment (P-256 ECDHE-PSK and Curve25519 SPEKE variants), CCM nonce/counters, security service characteristics and TLVs, ZVD provisioning | `panweave-direct::{session, secure, auth, tlv}` |
| 7 | ZDD behaviour: BLE advertising extension, commissioning service (form/permit/join/leave/status/manage joiners/identify/finding&binding), tunnel service (NPDU characteristic), trusted-link pre/post processing hooks into NWK | `panweave-direct::{advertisement, gatt}` (commissioning / tunnel: planned) |
| 8 | ZVD behaviour: discovery, security, reconnection, commissioning/tunnel clients, EUI-64 allocation | `panweave-direct::zvd` |
| 9–10 | Network key rotation with limited authorisation sessions; legacy-network support (ephemeral authorisation, routing on behalf of ZVD) | `panweave-direct::sessions` |

Security-sensitive: everything in chapters 6, 9, 10.

## SE1.4a — Smart Energy

Dependencies: R23.2, ZCL8 chapter 10, R23.2 Annex G (inter-PAN), sub-GHz
annexes (R23.2 Annex D.12–D.14).

| Area | Content | Owning module |
|---|---|---|
| 5.2–5.3 | Stack profile requirements, startup attribute set | `panweave-smart-energy::profile` |
| 5.4 | Security: preinstalled TCLKs, rejoin, leave, key updates, key usage per cluster, CBKE policies, TC swap-out | `panweave-smart-energy::security` |
| 5.5–5.14 | Commissioning, federated TC, multiple ESI, best practices, coexistence, multi-MAC | `panweave-smart-energy::commissioning` |
| 6 | Device specifications (ESI, meter, IHD, PCT, load control, range extender, smart appliance, prepayment terminal, physical device, remote comms) | `panweave-smart-energy::devices` |
| Annex A | Keep-Alive cluster, status enumerations | `panweave-zcl::clusters::keep_alive` |
| Annex B | Enhanced inter-PAN | `panweave-aps::interpan` |
| Annex C | Key Establishment cluster (CBKE suites 1 and 2) and test vectors | `panweave-smart-energy::key_establishment` |
| Annex D | DRLC, Metering, Price, Messaging, Tunneling, Prepayment, OTA, Calendar, Device Management, Events, Energy Management, MDU Pairing, Sub-GHz clusters | `panweave-smart-energy::clusters` |
| Annex E | Overlapping event rules | `panweave-smart-energy::events` |

Security-sensitive: all of §5.4, Annex C, per-cluster APS-encryption
requirements.
