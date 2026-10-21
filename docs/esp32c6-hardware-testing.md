# Hardware testing of the ESP32-C6 hub

How to bring up a hub on a real ESP32-C6 Super Mini and check real
Zigbee devices against it, reproducibly. The tools are part of
`panweave-hub-cli`; the diagnostics they rely on are described in
[esp32c6-diagnostics.md](esp32c6-diagnostics.md).

> **Status.** The smoke test and the hardware-in-the-loop (HIL) checks
> are implemented and compile; the protocol paths they use are tested in
> simulation. **They have not been run against a board yet** — no result
> in this repository is a hardware result. Every row of the compatibility
> matrix in `docs/esp32c6-hub.md` stays "Hardware Test Required" until
> a report from the procedure below exists for it.

## Contents

1. [Safety rules](#safety-rules)
2. [Setup](#setup)
3. [Smoke test](#smoke-test)
4. [Hardware-in-the-loop device checks](#hardware-in-the-loop-device-checks)
5. [Reports](#reports)
6. [USB reconnection checks](#usb-reconnection-checks)
7. [Hardening verification](#hardening-verification)
8. [Diagnosing a failing interview](#diagnosing-a-failing-interview)
9. [What to send with a bug report](#what-to-send-with-a-bug-report)

## Safety rules

The tools are built so that a test never costs the user their network:

* No test erases flash, factory-resets the hub or forms a new network.
  The smoke test reads state, or makes a change and undoes it (it writes
  the trace configuration back unchanged; it runs a 2 s capture).
* Two tests change more and run only when asked:
  * `--allow-reboot` resets the chip through the USB reset line and checks
    that the same network and registry come back;
  * `--join-test` opens the network for joining (default 120 s, at most
    254 s) and closes it afterwards.
* The HIL checks switch a light and wait for sensors; they never remove a
  device or change the network.
* A factory reset (BOOT held 10 s) or `espflash erase-region` are manual
  steps of `docs/esp32c6-hub.md`, never part of a test.

## Setup

1. Build and flash the hub (`docs/esp32c6-hub.md`, Building and Flashing),
   with `partitions-hub.csv`. Optionally check the table first:

   ```bash
   panweave-hub-cli partitions check examples/esp32c6-super-mini/partitions-hub.csv --image target/riscv32imac-unknown-none-elf/release/hub
   ```

2. Note the build id: `panweave-hub-cli diagnostics system` shows it
   (`-dirty` means uncommitted changes were built in).
3. Raise the trace level for the session if you will debug devices
   (default `info`):

   ```bash
   panweave-hub-cli diagnostics configure --level debug
   ```

## Smoke test

```bash
panweave-hub-cli self-test
```

```bash
panweave-hub-cli --json self-test --allow-reboot > smoke.json
```

| # | Test | PASS when | SKIP when |
|---|---|---|---|
| 1 | usb-port | the port opens (otherwise the CLI exits with code 3) | — |
| 2 | protocol | `GetHubInfo` answers with protocol v1 | — |
| 3 | boot-report | the boot report is complete enough (chip, USB); lists what is unavailable | 0.2.0 firmware |
| 4 | reset-reason | the last reset was not a watchdog reset | reason unavailable |
| 5 | partitions | the table was read, no findings, `hubdata` present | 0.2.0 firmware |
| 6 | storage | no I/O errors, damaged records or registry write errors | 0.2.0 firmware |
| 7 | network | network up, boot outcome not `read-failed` / `corrupt-not-formed`, registry count matches | — |
| 8 | radio | driver counters present, no configuration errors or transmit faults | no driver counters |
| 9 | runtime | watchdog armed, no loop turn over 500 ms | no loop timing |
| 10 | trace | no `error` / `critical` records stored | 0.2.0 firmware |
| 11 | admin-access | the trace configuration can be written (unchanged) and an invalid level is refused | 0.2.0 firmware |
| 12 | capture | a 2 s sanitized capture starts, is readable and stops by itself | firmware without `capture` (`NotSupported`) |
| 13 | usb-robustness | after line noise, a bad-CRC frame and an oversize frame the hub still answers | — |
| 14 | reboot-persistence | after a USB reset: same network, same device count, outcome `restored` | without `--allow-reboot` |
| 15 | join | a device joins and its interview completes within the window | without `--join-test` |

Exit code 0 when nothing FAILed (SKIPs are fine), 1 otherwise, 3 when the
hub cannot be reached. A failure's detail names the CLI command that
explains it.

Run the smoke test after every flash and before any device testing; keep
`smoke.json` with the results.

## Hardware-in-the-loop device checks

One device at a time, already paired (or pair it with `self-test
--join-test` or `permit-join`). The check is vendor neutral: it uses
only what the interview found and what the device reports.

```bash
panweave-hub-cli hil light 00124b002a3b4c5d --report bulb.json
```

```bash
panweave-hub-cli hil contact 00124b002a3b4c5d --report contact.json
```

```bash
panweave-hub-cli hil leak 00124b002a3b4c5d --report leak.json --wait 120
```

| Kind | Steps |
|---|---|
| all | `interviewed`: the interview finished (complete or partial); identity and category recorded |
| `light` | on, off, toggle, 50 % brightness, off — each must reach a command outcome; the operator confirms what the lamp did (`y` / `n`) |
| `contact` | the operator opens the contact, then closes it; each change must be reported within `--wait` seconds (default 60) |
| `leak` | the operator wets the probes, then dries them; the same |

* A step the device cannot do (no Level Control for brightness) is SKIP.
* `--unattended` never prompts: light steps PASS on the hub's
  confirmation alone ("not visually confirmed"); sensor steps SKIP.
* Sleepy sensors report when they wake; a change usually wakes them. If
  one does not report in time, the step FAILs with the command that
  shows its trace.

### v0.3.0 target devices

```bash
panweave-hub-cli hil aqara-leak 54ef4410xxxxxxxx --report aqara-t1.json --wait 120
```

```bash
panweave-hub-cli hil sber-contact a4c138xxxxxxxxxx --report sber-00030.json
```

```bash
panweave-hub-cli hil yandex-leak 0c4314xxxxxxxxxx --report yandex-00527.json --wait 120
```

Replace the addresses with the device's (`devices`). Steps, in order:

| Step | PASS when |
|---|---|
| `interviewed` | the interview finished |
| `profile` | the device's Basic identity matches the scenario's compatibility profile (FAIL: a different product, or the identity was not read) |
| `fingerprint` | a manufacturer name or model identifier was observed; the detail lists what the device did not report |
| `leak` / `open` | the operator triggers the sensor; the change is reported within `--wait` |
| `dry` / `close` | the operator clears it; the change is reported |
| `battery` | the device reported a battery voltage or percentage (SKIP when it has not reported yet: sleepy sensors report on their own schedule; never derived from the voltage) |
| `power-cycle` | the operator removes the battery for 10 s and puts it back; the hub hears the device again (no reset button, no re-pairing) |
| `leak-after-power-cycle`, `dry-after-power-cycle` (or `open…`, `close…`) | the sensor still reports after the power cycle |

Water: one drop across the probes, on a plate or a tile, **away from the
hub, the computer and any mains equipment**; dry the probes and the
surface afterwards. Nothing in these scenarios resets the device or the
hub or changes the network.

The run's `result` is `PASS` only if every step passed (with the
operator present), `FAIL` if any step failed, `INCOMPLETE` otherwise
(skipped steps, `--unattended`). The tool never changes a profile's
verification status: a `PASS` report from a real device is the evidence
for a reviewed change of `panweave_hub::compat` from
`DocumentedExternally` to `HardwareVerified`
([device-compatibility.md](device-compatibility.md#verification)).

`device <ieee> fingerprint [--json]` prints the identifying values with
their provenance (Observed on hardware, Documented externally, Derived
from protocol semantics, Unknown); attach it to a compatibility report.

## Reports

`hil --report` writes one JSON object:

| Key | Content |
|---|---|
| `tool` | CLI name and version |
| `kind` | `light`, `contact`, `leak`, `aqara-leak`, `sber-contact` or `yandex-leak` |
| `date` | when the report was written (UTC, RFC 3339) |
| `commit` | the git commit of the checkout the CLI ran in, `null` outside one |
| `result` | `PASS`, `FAIL` or `INCOMPLETE` (see above) |
| `hub` | hub IEEE and firmware |
| `build` | the firmware's build id |
| `profile`, `commercial_model`, `profile_verification` | the compatibility profile the device matches, `null` if none |
| `device` | IEEE, manufacturer, model, software build (firmware revision as the device reports it), category, power source, `fingerprint` (name, value, provenance) |
| `diagnostics` | `runtime` (the `diagnostics runtime` JSON) and `security` (the `security` JSON) at the end of the run |
| `operator_present` | false with `--unattended` |
| `steps` | name, status (`PASS` / `FAIL` / `SKIP`), detail, duration |
| `trace` | the device's trace records during the run (the JSONL schema of the diagnostics document) |

`self-test --json` prints `tool`, `passed`, `failed`, `skipped` and
`tests` (number, name, status, detail, duration).

To make a run reproducible, keep together: the build id, `smoke.json`,
the HIL reports, `diagnostics export --output run.jsonl`, and, for radio
problems, `capture export --output run.pcap --metadata run-frames.jsonl`.

## USB reconnection checks

Manual, about five minutes:

1. Start `panweave-hub-cli devices watch`; unplug the USB cable for 10 s
   (the hub is powered off); plug it back. The CLI ends with "serial port
   closed"; restart it — the network and devices are back
   (`diagnostics system`: reset reason `cold-boot`, network `restored`).
2. Power the hub from a USB charger, trigger sensors, then connect the
   computer: the hub kept working; `diagnostics runtime` shows how much
   output was discarded while nobody read.
3. Start `diagnostics watch`, then kill the CLI (close the terminal)
   instead of Ctrl+C; start it again: it resynchronizes at the next frame
   (no garbage, no reset — the reset reason is unchanged).
4. Open the port with another serial program at another baud rate, close
   it, run `panweave-hub-cli info`: it answers. If the chip reset, the
   boot report says `USB-JTAG reset`: that host's driver pulses DTR/RTS
   when opening the port — note the operating system.

## Hardening verification

What the security and reliability hardening needs confirmed on a real
board. Nothing here erases flash, factory-resets the hub or forces a
watchdog reset; steps that change state say so. Record each result with
the build id.

| # | Check | How | Expected |
|---|---|---|---|
| 1 | USB, chip, flash | `info`, `diagnostics system` | `ESP32-C6`, revision, 4096 KiB flash, build id |
| 2 | Boot report and network restore | `diagnostics system` after a power cycle | reset `cold-boot`, network `restored` |
| 3 | Capture-enabled build | default build; `capture export --seconds 30 --metadata m.jsonl` while a device talks | frames written; `m.jsonl` shows `redacted` with `captured_length` < `original_length` for data frames; Wireshark shows the payloads as cut |
| 4 | Capture-disabled build | `--no-default-features` build; `self-test` | test 12 SKIP (`NotSupported`); everything else as with capture |
| 5 | Memory, capture on vs off | `diagnostics runtime` in both builds after an hour of normal use | main stack watermark and heap present (not `unavailable`); the watermark of the capture-off build should be lower by about the capture buffer (≈ 2.5 KiB) — a lower bound, compare like with like |
| 6 | Loop timing, normal | `diagnostics runtime` after an hour | `loop_over_20ms` and overruns: record the values |
| 7 | Loop timing, diagnostics streaming | `diagnostics configure --level trace`, `diagnostics watch` for 10 min | longest loop turn and `loop_over_20ms` close to (6) |
| 8 | Loop timing, capture | `capture export --seconds 600` during sensor activity | as (7); `dropped` frames reported, not hidden |
| 9 | Key exchange (Zigbee 3.0 device) | `security`, then pair a device | `join-key-exchange-pending` then `join-authorized` in the trace; the device in `devices`; `security` shows no unauthorized device |
| 10 | Legacy device (if one is available) | pair it without an exemption, then with `security exempt <ieee> --seconds 120` | first: `join-key-exchange-timeout`, not registered; then: `key-exchange-exemption-used`, registered |
| 11 | Flash persistence | power cycle after (9)/(10) | devices back, authorization kept (`security`), exemptions kept |
| 12 | USB reconnection | the [USB reconnection checks](#usb-reconnection-checks) | as described |
| 13 | Watchdog, idle network | leave the hub with no devices (or only sleepy sensors) for an hour; `diagnostics runtime`, `diagnostics system` | no reset (uptime keeps growing), `health` `healthy-idle` or `healthy-active`, `radio recoveries 0`, no `stall-suspected` in the trace. A forced watchdog reset (to see `watchdog-reset` and `previous-stall-reset` in the boot report) is **not** part of this list: run it only on a board whose network may be lost, with explicit approval |
| 14 | Application-frame authorization | `security` after the devices of (9) worked for a while | denied counters by reason; a paired, authorized device has none counted against it in the trace |
| 15 | Sleepy devices pairing together | pair two or three sensors within a few seconds of each other | all authorized and interviewed; `diagnostics radio` may show the pending table full — record the count |

Simulator results are not ESP32-C6 measurements: timing and memory rows
need the board.

## Diagnosing a failing interview

> **Illustrative example — not a hardware result.** The session below is
> constructed to show how the tools read; the device, addresses and
> timings are invented. No real device was tested.

A sleepy contact sensor joined but `devices` shows its interview
`in-progress` for minutes:

```text
$ panweave-hub-cli diagnostics interview 00:12:4b:00:aa:bb:cc:dd
#41      1203.450 s info     trust-center  join-key-sent 00:12:4b:00:aa:bb:cc:dd nwk 0x5a1f (+38 ms)
#42      1203.512 s info     trust-center  join-key-delivered 00:12:4b:00:aa:bb:cc:dd nwk 0x5a1f (+62 ms)
#45      1204.020 s info     commissioning device-announced 00:12:4b:00:aa:bb:cc:dd nwk 0x5a1f
#46      1204.021 s info     interview     interview-started 00:12:4b:00:aa:bb:cc:dd stage node-descriptor step 0
#47      1204.022 s debug    interview     interview-request 00:12:4b:00:aa:bb:cc:dd tsn 12 stage node-descriptor step 0 attempt 1
#48      1205.310 s debug    interview     interview-answer 00:12:4b:00:aa:bb:cc:dd tsn 12 stage node-descriptor step 0
#49      1205.311 s debug    interview     interview-request 00:12:4b:00:aa:bb:cc:dd tsn 13 stage active-endpoints step 0 attempt 1
#51      1206.398 s debug    interview     interview-answer 00:12:4b:00:aa:bb:cc:dd tsn 13 stage active-endpoints step 0
#52      1206.400 s debug    interview     interview-request 00:12:4b:00:aa:bb:cc:dd ep 1 tsn 14 stage simple-descriptors step 0 attempt 1
#55      1216.401 s warning  interview     interview-timeout 00:12:4b:00:aa:bb:cc:dd ep 1 tsn 14 stage simple-descriptors step 0 attempt 1
#56      1218.402 s debug    interview     interview-request 00:12:4b:00:aa:bb:cc:dd ep 1 tsn 15 stage simple-descriptors step 0 attempt 2
#59      1228.403 s warning  interview     interview-timeout 00:12:4b:00:aa:bb:cc:dd ep 1 tsn 15 stage simple-descriptors step 0 attempt 2
#60      1230.404 s debug    interview     interview-request 00:12:4b:00:aa:bb:cc:dd ep 1 tsn 16 stage simple-descriptors step 0 attempt 3
#63      1240.405 s warning  interview     interview-timeout 00:12:4b:00:aa:bb:cc:dd ep 1 tsn 16 stage simple-descriptors step 0 attempt 3
#64      1240.406 s warning  interview     interview-stalled 00:12:4b:00:aa:bb:cc:dd stage simple-descriptors step 0 after timeouts
--- summary
requests 5, answers 2, timeouts 3, steps skipped 0, stalls 1, resumptions 0
last stage seen: simple-descriptors
  interview-stalled stage simple-descriptors step 0 after timeouts
```

Reading it: the key reached the device and it announced itself, so the
join is fine. It answered the first two requests, then three Simple_Desc
requests went unanswered — it went to sleep right after joining. Next
steps:

* `diagnostics radio`: is `nwk_pending_held` at the capacity (4)? Then
  the requests could not even be queued for it.
* Wake the device (press its button, open the contact): the interview
  resumes when the hub hears it (`interview-resumed`).
* `capture export --seconds 60` while waking it: the pcap shows whether
  the device polls and whether the hub's indirect frame went out (match
  the TSN).

## What to send with a bug report

* The build id (`diagnostics system`), the smoke test JSON, the HIL
  report if any.
* `diagnostics export --output trace.jsonl` (raise the level to `debug`
  and reproduce first).
* For radio or join problems, a sanitized capture (`capture export`,
  the default); a raw one (`--mode raw --allow-raw`) only if asked, and
  never of a network you want to keep — it may contain the network key.
* The device's manufacturer and model as the hub read them
  (`device <ieee>`), never guesses.
