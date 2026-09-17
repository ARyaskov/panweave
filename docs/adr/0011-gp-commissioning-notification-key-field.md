# ADR-0011: GP Commissioning Notification carries no GPD key field

* Status: accepted
* Date: 2026-09-17
* Specification: `GP Basic 1.1.2 §A.3.3.4.3` (Figure 30, Figure 31),
  `§A.3.9.2.1.1`, `§A.4.1` (Table 54), `§A.1.5.4.1`

## Context

§A.3.9.2.1.1 says that a proxy which security-processes a protected
Commissioning GPDF successfully "schedules transmission of GP
Commissioning Notification with the fields GPD security key and GPD
security frame counter … present" and "GPD key present set to 0b1".
Figure 30 / Figure 31 define the GP Commissioning Notification without a
GPD key field and without a "GPD key present" option bit: the Options
field carries ApplicationID, RxAfterTx, SecurityLevel, SecurityKeyType,
SecurityProcessingFailed, BidirectionalCapability and ProxyInfoPresent
only, and the payload ends with the proxy info and the MIC.

Similarly, the security test vectors of §A.1.5.4 label GPD CommandID
0x20 "OFF", while Table 54 assigns 0x1F to Off and 0x20 to On.

## Decision

* The codec and the proxy follow Figure 30 / Figure 31: no key is ever
  placed in a GP Commissioning Notification. The key type used is reported
  in the SecurityKeyType sub-field; a sink that needs the key derives or
  looks it up itself (it holds the shared keys and receives individual keys
  in the Commissioning GPDF payload, which the proxy forwards unmodified).
* The command identifiers follow Table 54 (`command::OFF` = 0x1F,
  `command::ON` = 0x20); the test vectors are used for their frame and
  MIC bytes only.

## Consequences

* A sink implementation from another vendor that expected a key field after
  the frame counter would mis-parse our notifications; none is known, and
  Figure 30 is the normative frame format.
* Should a later revision add the key field with an explicit option bit, the
  codec gains an optional field without changing the existing layout.
