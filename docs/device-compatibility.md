# Device compatibility

How the Panweave hub (`panweave-hub`, ESP32-C6 image) handles commercial
Zigbee devices, what is known about the v0.3.0 target devices, where
that knowledge comes from, and how it is verified.

> **Status.** No commercial device has been run against the hub. Every
> statement below about a product comes from public documentation and
> open-source integrations, and the hub's handling of it is tested in
> simulation with **synthetic fixtures** — the simulator's standard IAS
> sensor answering with the product's documented identity strings.
> Every profile's verification status is `DocumentedExternally`.

## Contents

1. [Principles](#principles)
2. [Compatibility profiles](#compatibility-profiles)
3. [Aqara Water Leak Sensor T1](#aqara-water-leak-sensor-t1)
4. [Sber opening sensor SBDV-00030](#sber-opening-sensor-sbdv-00030)
5. [Yandex water leak sensor YNDX-00527](#yandex-water-leak-sensor-yndx-00527)
6. [Sber SBDV-00115: out of scope](#sber-sbdv-00115-out-of-scope)
7. [IAS Zone and battery handling](#ias-zone-and-battery-handling)
8. [Sleepy devices](#sleepy-devices)
9. [Fingerprints](#fingerprints)
10. [Verification](#verification)
11. [Sources](#sources)

## Principles

* **Generic first.** Every device is handled by the same
  standards-based path: interview (node, active endpoint and simple
  descriptors, Basic attributes), capability and category derivation
  from the clusters it declares, IAS Zone enrolment and interpretation
  per zone type, Power Configuration reporting. A device works without a
  profile.
* **Profiles are narrow.** A profile (`panweave_hub::compat`) matches an
  exact Basic `ManufacturerName` / `ModelIdentifier` pair — or an exact
  model identifier plus a documented suffix — never a manufacturer alone
  or a prefix. Other products from the same vendor, and other Tuya
  `TS0203` sensors, do not match.
* **Profiles never touch security.** The identity strings are reported by
  the device and authenticate nothing. Joining, the Trust Center policy,
  application-frame authorization and key-exchange exemptions ignore
  profiles entirely; a profile cannot admit a device.
* **Evidence or nothing.** Every profile and every correction cites its
  evidence; nothing is inferred from a product description. Values the
  sources do not state are left unknown, never filled in.
* **Verification is explicit.** A profile is `DocumentedExternally` until
  a hardware report (`hil … --report`) from a real device justifies a
  reviewed code change to `HardwareVerified`.
* No code was copied from other projects; the open-source integrations
  cited below (MIT licensed) were read as documentation of device
  behaviour.

## Compatibility profiles

| Profile id | Product | Match | Correction | Verification |
|---|---|---|---|---|
| `aqara-water-leak-t1` | Aqara Water Leak Sensor T1 (WL-S02D, SJCGQ12LM) | `LUMI` / `lumi.flood.agl02`, also `lumi.flood.agl02` followed by a tab and a firmware suffix | battery powered despite the MAC "mains powered" flag | documented externally |
| `sber-opening-sensor` | Sber Smart Opening Sensor (SBDV-00030) | `_TYZB01_epni2jgy` / `TS0203` | none | documented externally |
| `yandex-water-leak-00527` | Yandex Water Leak Sensor (YNDX-00527) | any manufacturer / `YNDX-00527` | none | documented externally |

A profile is looked up from the identity the interview read (Basic
attributes 0x0004 and 0x0005); until then the device is handled
generically. Tests: `panweave-hub/src/compat.rs` (exact matching),
`panweave-hub/src/hub.rs` (`the_aqara_profile_corrects_a_mains_claim_and_others_do_not`),
`panweave-hub/tests/hub_devices.rs`.

## Aqara Water Leak Sensor T1

The [physical Aqara investigation](aqara-leak-investigation.md) records
successful pairing, required unique TCLK verification, complete interview,
IAS enrollment and three leak/dry cycles for LUMI / lumi.flood.agl02.
The unit reports battery power and 3000 mV, without a percentage. Its
association capability is 0x80, so the 0x84 correction described below
has not been exercised by this physical unit. A subsequent manual power-loss
test restored the network and all three registry entries; Aqara resumed
leak/dry reporting without re-pairing. Long-term stability remains unverified.

* **Identity**: manufacturer `LUMI`, model `lumi.flood.agl02`; a firmware
  variant reports `lumi.flood.agl02` followed by a tab and further bytes
  (both appear in the zigbee-herdsman-converters definitions SJCGQ12LM
  and SJCGQ12LM-ES). Manufacturer code 0x115F (Lumi). Also sold as
  Yandex YNDX-00521 (a white label listed by Zigbee2MQTT) — a different
  product from the Yandex YNDX-00527 below.
* **Descriptors** (from a device signature published in
  zha-device-handlers issue #2582): endpoint 1, profile 0x0104, device
  0x0402 (IAS Zone); input clusters 0x0000, 0x0001, 0x0003, 0x0500;
  output 0x0019; Basic PowerSource 3 (battery); zone type 0x002A (water
  sensor).
* **Deviation**: the MAC capability octet (association request and node
  descriptor) is 0x84 — *mains powered* and *receiver off when idle* —
  although the device runs on a CR2032. The generic path would classify
  it as mains powered from that flag; the profile ignores the flag, so
  the device is battery powered (from Basic PowerSource when read).
  This is the only correction.
* **Battery**: Power Configuration BatteryVoltage (0x0020) is used;
  per the signature BatteryPercentageRemaining is not supported, so the
  percentage stays unknown — the hub does not derive one from the
  voltage. The manufacturer-specific cluster 0xFCC0 (which carries the
  voltage in millivolts among other values) is not read: the hub has no
  client for it. Limitation, documented.
* **Alarm**: IAS ZoneStatus Alarm1 = water (generic water-sensor rule).
* **Not done**: no Lumi-specific configuration (the herdsman definition
  performs an IAS enrolment and sets a check-in interval; the hub's
  generic enrolment covers the former; the latter is not needed for
  correctness).

## Sber opening sensor SBDV-00030

Physical association debugging and the shared-Flash adapter correction
are recorded in [Sber contact investigation](sber-contact-investigation.md).
Hardware key delivery, unique TCLK verification, IAS enrollment, three
closed/open pairs and battery reports passed for a user-identified Sber
unit with manufacturer `_TYZB01_nnv2dy5m`, model `TS0203`. This is a different
fingerprint from the exact profile below; generic handling works without
corrections. Its interview remains partial because Configure Reporting on
Power Configuration was rejected (0x82). A manual hub power-loss run also
restored both this sensor and Yandex reporting without re-pairing; two
link keys and the security policy were retained. Its retail SKU and
long-term stability remain unverified.

* **Identity**: manufacturer `_TYZB01_epni2jgy`, model `TS0203` (a Tuya
  platform device). Only this exact pair matches: the many other
  `TS0203` sensors have other manufacturer strings.
* **Behaviour** (zigbee-herdsman-converters definition SBDV-00030): IAS
  contact sensor with Alarm1 = open, tamper and battery-low bits; battery
  voltage reporting; it sends unsolicited Basic cluster reports, which
  that integration ignores. The hub has no Basic client on its endpoint,
  so such reports are not delivered to it in the first place — no
  correction needed.
* **Zone type**: read at the interview; the sources do not state it, so
  nothing is assumed. A contact sensor that reports the contact
  zone type (0x0015) is interpreted as contact; another type is
  interpreted by its own rule.
* **Correction**: none.

## Yandex water leak sensor YNDX-00527

* **Identity**: model `YNDX-00527`; the profile does not constrain the
  manufacturer string (the source names only the model).
* **Behaviour** (zigbee-herdsman-converters definition YNDX_00527; Yandex
  specifications): Zigbee 3.0, CR2032, IAS water leak (Alarm1) and
  battery low, battery voltage; operating temperature +5 to +40 °C.
* **Zone type**: read at the interview; expected to be a water sensor
  (0x002A) given the documented semantics, but not assumed.
* **Correction**: none.

## Sber SBDV-00115: out of scope

The Sber smart LED bulb SBDV-00115 (E27) uses Wi-Fi 802.11 b/g/n
(2.4 GHz) and Bluetooth LE 4.2 only, per the manufacturer's
specifications. It is **not a Zigbee device**: the hub has no profile for
it, no scenario pairs it, and no fingerprint for it exists or was
invented. It is listed in `panweave_hub::compat::OUT_OF_SCOPE` with the
reason.

## IAS Zone and battery handling

* **States** are three-valued: `Unknown`, then `Dry` / `Leak` or
  `Closed` / `Open`. They stay `Unknown` until the device reports (after
  a hub restart too: the registry restores identities, not stale states)
  and when the zone type does not define the semantics.
* **Raw status kept**: the last raw ZoneStatus is stored with the device
  and every `ias-zone` trace record carries the raw value next to the
  interpretation (`docs/esp32c6-diagnostics.md`).
* **Early notifications**: a Zone Status Change Notification that arrives
  before the zone type was read is stored raw and interpreted as soon as
  the type is known (v0.3.0; previously it stayed uninterpreted until the
  next change).
* **Battery percentage**: BatteryPercentageRemaining is in half percent,
  0..=200; 0xFF (invalid) and values above 200 (out of range) are
  ignored (v0.3.0; previously values above 200 showed as 100 %). Odd
  values round up (151 → 76 %).
* **Battery voltage**: BatteryVoltage in 100 mV units; 0 and 0xFF are
  ignored. No percentage is derived from a voltage.
* **Battery low**: the IAS battery bit and BatteryAlarmState bit 0.

## Sleepy devices

All three targets are sleepy end devices: whatever the hub sends waits
for the device's next poll, in one of the stack's four NWK pending slots
(`PENDING_TX`). Simulation showed a real failure when three sleepy
sensors paired within seconds: the pending table filled, the APS layer
retried refused frames in the same instant and gave up, the Trust
Center's key-exchange replies were lost, and the sensors were removed
for not completing the key exchange. Fix (v0.3.0, `panweave-aps`): a
frame refused for lack of NWK buffers is offered again after 1 s, at
most 8 times. `PENDING_TX` is unchanged (4). RAM cost: none measured —
an APS pending entry is 448 octets on the host with or without the new
counter, which fits in existing padding. Tests: `hub_devices::three_sleepy_sensors_joining_at_once_all_complete_their_interviews`,
`…_paired_seconds_apart_…`, `panweave-aps` `layer` tests
`a_frame_the_nwk_cannot_buffer_is_offered_again_later`,
`local_refusals_are_bounded`.

## Fingerprints

```bash
panweave-hub-cli device 54ef4410xxxxxxxx fingerprint --json
```

Prints every identifying value with its provenance:

| Label | Meaning |
|---|---|
| Observed on hardware | reported by the device over the air and stored by the hub the CLI is attached to |
| Documented externally | from the matching compatibility profile (vendor, commercial model, evidence, verification) |
| Derived from protocol semantics | computed by the hub (category, capabilities, interview status, a profile's power-source correction) |
| Unknown | not reported; never filled in from elsewhere |

Model identifiers are printed exactly, control characters escaped
(`lumi.flood.agl02\tF\x01`).

## Verification

| Device | Implemented | Verified in simulation | Hardware |
|---|---|---|---|
| Aqara T1 | profile, correction, generic IAS / battery | synthetic identity: join, key exchange, interview, alarms, rejoin, restart, concurrent pairing | Hardware Test Required |
| Sber SBDV-00030 | profile, generic IAS / battery | synthetic identity: same | Hardware Test Required |
| Yandex YNDX-00527 | profile, generic IAS / battery | synthetic identity: same | Hardware Test Required |
| Sber SBDV-00115 | excluded (not Zigbee) | — | — |

To verify a device: `hil aqara-leak|sber-contact|yandex-leak <ieee>
--report FILE` ([esp32c6-hardware-testing.md](esp32c6-hardware-testing.md#v030-target-devices)).
A `PASS` report plus the fingerprint is what a change of the profile's
`verification` to `HardwareVerified` must cite; the test
`every_profile_is_documented_and_none_is_claimed_verified` has to be
updated in the same change. If a device deviates (a different zone type,
an alarm on another bit, a missing attribute), capture it
(`capture export`, the trace) before adding a correction.

## Sources

* Zigbee2MQTT device pages: SJCGQ12LM, SBDV-00030, YNDX-00527
  (https://www.zigbee2mqtt.io/devices/).
* zigbee-herdsman-converters (MIT), `src/devices/lumi.ts`, `sber.ts`,
  `yandex.ts` (https://github.com/Koenkk/zigbee-herdsman-converters).
* zha-device-handlers issue #2582, Aqara T1 water leak sensor signature
  (https://github.com/zigpy/zha-device-handlers/issues/2582).
* Manufacturer specifications: Aqara Water Leak Sensor T1; Yandex
  YNDX-00527; Sber SBDV-00030 and SBDV-00115.
