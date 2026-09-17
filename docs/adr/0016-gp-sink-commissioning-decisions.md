# ADR-0016: Green Power sink commissioning decisions left open by the specification

* Status: accepted
* Date: 2026-09-18
* Specification: `GP Basic 1.1.2 §A.3.3.2.4–A.3.3.2.6`, `§A.3.5.2.4`,
  `§A.3.6.1.3`, `§A.3.9.1` (steps 7, 13, 18, 19), `§A.3.9.2.1.2`,
  `§A.4.2.1.1.3`, `§A.1.5.2.1.2`

## Context

The sink side of the commissioning procedure is written as a recommended
procedure with a number of "vendor- and application-specific" points.
`panweave_green_power::sink::Sink` has to pick one behaviour for each of
them, and a few frame-level details are not spelled out either.

1. **Which key a sink hands out.** Step 13.j.i only says which key to
   send when the GPD included an OOB key and `gpSharedSecurityKeyType` is
   set. §A.3.9.2.1.2 requires the sink to "include the key" when the GPD
   announced `KeyType` 0b000 with a key request, without saying which.
2. **The frame counter of the key protection.** §A.3.7.1.2.3 protects the
   Commissioning Reply's key with "the frame counter of the GPDF that
   triggered the reply", but the Commissioning GPDF is always unprotected
   and carries no security frame counter in its NWK header.
3. **The exit conditions.** `gpsCommissioningExitMode` defaults to "on
   first pairing success" only (0x02), while `gpsCommissioningWindow` is
   "the time during which this sink accepts pairing changes".
4. **When the sink's own gpTxQueue is served.** Step 13.d serves the queue
   before step 13.j builds the reply, which reads as if the reply were
   sent on the *next* GPDF with RxAfterTx; §A.1.5.2.2 serves the queue for
   the GPDF just received, gpTxOffset after it.
5. **A Data GPDF with Auto-Commissioning** has no DeviceID; the Sink
   Table's DeviceID parameter is mandatory.
6. **Sequence numbers of unsecured pairings.** The Sink Table stores "the
   last observed valid frame counter", which for SecurityLevel 0b00 is the
   MAC sequence number; §A.3.6.1.3 accepts any number that passes the
   duplicate filter.
7. **Direct Channel Requests.** Step 7.d.iii has a sink that appoints
   itself SelectedSender switch to the GPD's next channel and listen there
   for up to 5 s.

## Decision

1. A key request is answered with the `gpSharedSecurityKeyType` key
   (`GroupKey`, `NwkKey`, `NwkDerivedGroupKey`, or a `DerivedIndividual`
   key computed from the shared key); when no shared key type is
   configured the NWK-key derived group key (0b011) is used, since every
   network device can derive it. The agreed key (type and value) is what
   the Sink Table entry and the GP Pairing carry.
2. The `GPDoutgoingCounter` of the triggering Commissioning command is the
   frame counter of the key protection and is echoed in the reply's Frame
   Counter field; a Commissioning command without the counter is refused
   when security is in use (`Refusal::MissingCounter`).
3. The window always ends commissioning mode (`SinkEvent::CommissioningMode(None)`,
   no GP Proxy Commissioning Mode exit: the proxies were given the same
   window); `ON_FIRST_PAIRING` additionally exits after a pairing and tells
   the proxies when they were involved. `ON_EXIT_COMMAND` only shapes the
   Exit Mode sent to the proxies.
4. The gpTxQueue is served for the GPDF that carries RxAfterTx, including
   the Commissioning GPDF whose processing just queued the reply, gpTxOffset
   (20 ms) after the indication. The runtime measures the offset from the
   indication rather than from the start of the reception on the medium;
   the 5 ms `gpMaxTxOffsetVariation` is the hardware budget
   (`requires-hardware-validation`).
5. Such pairings record DeviceID 0xFE (`DEVICE_ID_GENERIC`), the generic
   identifier of a GPD whose functionality is described by its commands.
6. The MAC sequence number of the pairing frame is stored and later MAC
   sequence numbers are recorded without a persistence event; freshness for
   SecurityLevel 0b00 is the duplicate filter only.
7. The sink answers a direct Channel Request only when the GPD listens on
   the operational channel (Auto-Commissioning clear on that request); it
   never leaves the operational channel. Through a proxy it appoints the
   proxy as SelectedSender on the GPD's announced next channel (GP
   Response). A GPD that cycles through the channels reaches the
   operational one within its attempts.

## Consequences

* A GPD that expects the OOB key it supplied to remain in use while also
  asking for a key gets the shared key instead (as step 13.j.i prescribes)
  only when `gpSharedSecurityKeyType` is configured; otherwise its own key
  is kept.
* Sinks that must stay in commissioning mode indefinitely pass a long
  window to `enter_commissioning_mode`.
* The Translation Table is not implemented; a GPD announcing
  "Application Description follows" is paired once every report
  descriptor arrived, and its compact attribute reports are interpreted
  through those descriptors into Report Attributes for the paired local
  endpoints. GP Pairing Configuration carrying report descriptors
  (Action 0b101) is refused.
