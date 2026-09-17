# ADR-0013: Enhanced inter-PAN security — exempt cluster and authenticated data

* Status: accepted
* Date: 2026-09-17
* Specification: `SE 1.4a Annex B.4` (stub APS header, Security sub-field
  rule), `B.8` (security requirements), `R23.2 Annex G.3.3` (inter-PAN APS
  header), `R23.2 §4.4.1.1` (APS frame security)

## Context

Annex B.4 states that, for the Smart Energy profile identifier, the
Security sub-field of the stub APS frame control "shall be set to 0" when
"the cluster ID is set to 0x0019 (Key Establishment)" and to 1 otherwise.
Cluster 0x0019 is the OTA Upgrade cluster; Key Establishment is 0x0800 in
Table 5-14 and in Annex C. The sentence names the cluster whose frames
cannot be secured because they are the ones that create the link key, so
the identifier is an erratum.

Annex B also says a secured frame carries an APS auxiliary header and
that the resulting APS link key "secures all further Enhanced Inter-PAN
frames", but neither Annex B nor Annex G says which octets form the
authenticated data of the CCM* computation: only the stub APS header and
the auxiliary header, as for a networked APS frame (§4.4.1.1 step 4,
where the a-data is the APS header || auxiliary header), or the stub NWK
header as well.

## Decision

* `panweave-smart-energy::interpan::security_required` exempts Key
  Establishment (0x0800) and nothing else; OTA Upgrade frames over
  inter-PAN require security like every other cluster. An implementation
  that followed the printed identifier literally would send its CBKE
  frames secured with a key it does not have yet, so the literal reading
  cannot be what the profile intends.
* `panweave-aps::interpan::secure` / `unsecure` apply the ordinary APS
  frame security of §4.4.1.1 to the frame starting at the APS frame
  control: the stub NWK header is neither encrypted nor authenticated,
  exactly as the NWK header of a networked frame is outside the APS
  security envelope. The extended nonce is always used on transmission so
  that a receiver that knows the sender only by its MAC source address
  can still locate the key.

## Consequences

* Interoperability with a stack that includes the two stub NWK octets in
  the a-data would fail the MIC check; the choice is isolated in
  `panweave-aps::interpan` and can be revisited from a captured frame.
* Conformance item `PW-SE-CL-009` stays `requires-hardware-validation`
  for the a-data boundary until a capture from another vendor confirms
  it; the codec, policy and CBKE-over-inter-PAN flow are implemented.
