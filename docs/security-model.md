# Panweave security model

This document describes the trust boundaries, threat assumptions, and the
concrete mechanisms Panweave uses to satisfy the security requirements of
R23.2 chapter 4, BDB 3.1, GP 1.1.2, ZD 1.1 and SE 1.4a. Section references
follow `docs/specification-map.md`.

## Trust boundaries

```
                    untrusted                     trusted
  ┌─────────────┐   radio     ┌───────────────┐   API    ┌──────────────┐
  │ any 802.15.4│ ──────────► │  panweave-mac │ ───────► │ application  │
  │ transmitter │             │  nwk/aps/...  │          │ code         │
  └─────────────┘             └──────┬────────┘          └──────────────┘
                                     │ storage trait
  ┌─────────────┐   BLE       ┌──────┴────────┐
  │ any BLE     │ ──────────► │ panweave-     │  keys, counters, tables
  │ central     │             │ direct        │  (trusted at rest only if
  └─────────────┘             └───────────────┘   the backend protects them)
```

* **All radio input is attacker-controlled.** Every byte received from the
  MAC is parsed with bounded, panic-free decoders. Malformed frames are
  dropped according to R23.2 §1.2.5 (drop silently, do not respond, do not
  update state), and counted in diagnostics.
* **All BLE input is attacker-controlled** (Zigbee Direct). Characteristic
  writes are validated before any state change; no unauthenticated write can
  alter network state (ZD1.1 §6, §7.7.2.2).
* **Application code is trusted** but the public API refuses operations that
  would violate protocol policy (e.g. transmitting a NWK command without
  NWK security on a secured network).
* **Storage backends are trusted to be honest** (they return what was
  written). Confidentiality at rest is the integrator's responsibility; the
  storage model documents which records contain secrets.

## Assets

| Asset | Where | Notes |
|---|---|---|
| Network key(s) + sequence numbers | `SecurityMaterial` in `panweave-security`, persisted | Never logged; `Debug` redacted. |
| Trust Center link keys (global, unique, negotiated) | `LinkKeyTable` | Per-device entries carry `KeyAttributes` (provisional / unverified / verified). |
| Application link keys | `LinkKeyTable` | Same table, different `KeyType`. |
| Install codes / passphrases | Transient during commissioning; hashed to keys | Zeroized after derivation. |
| Outgoing frame counters | Persisted with reservation windows | See "Frame counters". |
| Incoming frame counters per neighbor/device | RAM, optionally persisted | Reset rules follow §4.3.4. |
| DLK ephemeral secrets | Stack-local, zeroized | Curve25519 / P-256 private scalars. |
| Zigbee Direct session keys | `panweave-direct::Session` | Bound to one BLE connection. |

## Cryptographic primitives

* AES-128 block cipher: RustCrypto `aes` (constant-time software
  implementation, or hardware via the `Aes128Cipher` trait).
* CCM*: implemented in `panweave-security::ccm` following R23.2 Annex A,
  because Zigbee requires the M = 0 (encryption-only) variant and the
  specific nonce layout. Verified against Annex C test vectors.
* AES-MMO hash and HMAC (R23.2 Annex B.6, B.1.4): `panweave-security::mmo`.
* Curve25519 (DLK, R23.2 Annex J; ZD SPEKE) via `x25519-dalek`.
* P-256 ECDHE (ZD1.1 §6.5.1.2) via `p256`.
* SHA-256 / HMAC-SHA-256 via `sha2` / `hmac`.
* Randomness is injected through `panweave_types::rng::CryptoRng`; the core
  never calls a global RNG. Test builds use a seeded deterministic RNG that
  is **not** a `CryptoRng` implementation for production.

## NWK security (R23.2 §4.3)

* Outgoing NWK frames on a secured network are always protected with the
  active network key at security level 5 (ENC-MIC-32) unless the frame is one
  of the explicitly permitted unsecured frames (rejoin request in the
  unsecured rejoin case, network commissioning request as specified).
* Incoming frames are decrypted with the key whose sequence number matches
  the auxiliary header; an unknown sequence number causes a drop.
* Incoming frame counters are tracked per source extended address; frames
  whose counter is not strictly greater than the stored value are rejected
  (replay protection). On a key switch the incoming counters are reset and
  the outgoing counter is reset to zero only when it exceeds 0x8000_0000
  (§4.3.4); otherwise it continues, so a value is never reused under the
  new key either.
* The outgoing frame counter is monotonic across reboots (see below) and
  triggers a network-key update request when approaching exhaustion.

## APS security (R23.2 §4.4)

* Link-key encrypted commands (transport key, remove device, request key,
  switch key, verify key, confirm key, key negotiation) enforce the key
  requirements per command in §4.4.11.
* Tunnel commands are only accepted from the Trust Center / parent as
  specified.
* Key attributes (provisional / unverified / verified) gate what a link key
  may protect (§4.7.3, BDB §7.2).
* `Debug` on key material and secured frames prints `[REDACTED]`.

## Trust Center policy (R23.2 §4.7.1, BDB §5.6)

Policy is an explicit `TrustCenterPolicy` struct evaluated by
`panweave-security::trust_center` on every join, rejoin, key request,
key negotiation request and interview step. Defaults follow the mandatory
BDB 3.1 values (unique TCLK required, install-code aware, `allowRejoins`,
`allowTCLinkKeyRequests` etc.). There is no code path that bypasses the
policy "for interoperability".

## Frame counters and persistence

Frame-counter rollback after power loss would allow replay and nonce reuse.
Panweave uses a **reservation window** strategy (`docs/storage-model.md`):

1. On boot, the persisted `reserved_until` value is loaded; the in-RAM
   counter starts at `reserved_until` (never at the last used value).
2. Before the counter reaches `reserved_until`, a new reservation of
   `window` (default 1024) is committed transactionally.
3. Commit is required to be atomic by the storage backend; if the commit
   fails, transmission is refused rather than reusing counters.

The same mechanism protects APS frame counters, Green Power sink-side
counters (where the spec requires persistence) and Zigbee Direct counters.

## Commissioning trust (BDB 3.1)

* Joining uses install-code derived keys, the well-known global key only
  where the policy allows it, or DLK (R23 key negotiation).
* After joining a centralized network, a unique TCLK is required before
  the node is considered fully commissioned; failure follows the BDB
  procedure (leave if `bdbTCLinkKeyExchangeAttemptsMax` is exhausted).
* Device interview (R23.2 §2.4.3.4, BDB §9.9): the Trust Center withholds
  authorisation (`Update Device` handling, authorisation token) until the
  interview completes according to policy.

## Dynamic Link Key negotiation (R23.2 §4.4.9, §4.6.3.5, §4.7.3.3)

Implemented in `panweave-runtime::dlk` over the ZDO security services of
`panweave-zdo::security` (feature `dlk`, Curve25519 via `x25519-dalek`):

* The joiner advertises SPEKE in the Supported Key Negotiation Methods
  TLV of its Network Commissioning Request. The Trust Center selects the
  pre-shared secret from its key-pair entry: an install-code derived key
  (authenticated) or, only under `InstallCodePolicy::OptionalWithAnonymousNegotiation`,
  the well-known passphrase (anonymous).
* Security_Start_Key_Update_req / Security_Start_Key_Negotiation_req/rsp
  travel through the parent's Relay Message commands (or directly, NWK
  unsecured, when the Trust Center is the parent); the joiner then proves
  the derived key with Verify Key and the Trust Center confirms before
  transporting the network key. What a joiner accepts unsecured during
  this phase is fixed by ADR-0008.
* Both sides back the previous key-pair entry up and restore it when the
  exchange fails or `apsSecurityTimeOutPeriod` expires; no partial key
  material survives a failure.
* After the join the device fetches its authentication token once
  (Security_Retrieve_Authentication_Token); the Trust Center locks the
  entry (`PassphraseUpdateAllowed = FALSE`). Later negotiations use the
  token and are therefore authenticated.
* A key established by negotiation cannot be downgraded through Request
  Key (`TrustCenterPolicy::allow_tclk_request` refuses negotiated
  entries).

## APS frame counter verification (R23.2 §4.6.3.8)

Each key-pair entry carries `VerifiedFrameCounter`. Fresh entries created
by a key transport or negotiation are verified; a warm start marks every
entry unverified. An APS-encrypted frame from a partner that supports
synchronization (Link-Key Features bit 0, assumed for negotiating
partners) is authenticated and then dropped while the entry is
unverified, and a Security_Challenge_req is sent (one outstanding
challenge, `apsChallengePeriodTimeoutSeconds` rate limit). The response
MIC is computed with the link key XORed with the responder's outgoing
counter and a nonce built from `apsChallengeFrameCounter`, so a replayed
response cannot advance the counter; on success the incoming counter is
set to the reported value.

## Zigbee Direct boundary

BLE transport is abstract. `panweave-direct` treats every GATT write as
untrusted, performs session establishment before any commissioning or tunnel
operation, enforces counter monotonicity on the secured characteristic
channel, and never exposes the network key over an unauthenticated session.

## Denial of service and table exhaustion

* All tables are bounded; the drop policy per table:
  * neighbor table: never evict a child; evict oldest non-child, non-parent
    entry with the worst link cost when required by the spec's discovery
    semantics; otherwise refuse.
  * route discovery table: reuse the oldest expired entry; drop new
    discoveries when full (route request is not forwarded).
  * broadcast transaction table: when full, the broadcast is not relayed and
    the failure is reported to the application if locally originated.
  * APS duplicate rejection table: oldest entry overwritten (bounded replay
    window; documented as a trade-off).
  * APS reassembly: at most `N` concurrent transactions, new ones refused
    with `Status::InsufficientSpace`.
  * GP proxy/sink tables: full is reported via status; entries are never
    silently replaced.
* Route request floods are rate-limited by the route discovery table and
  `nwkcRREQRetries` semantics; broadcast storms are bounded by the BTT and
  the passive-ack timer.
* Security processing failure paths do not allocate.
* Frame processing is bounded by frame size (127 octets on 2.4 GHz); no
  algorithm is worse than O(table size) per frame.

## Logging

Logging back-ends receive structured events with addresses, identifiers,
counters and status codes only. Keys, passphrases, install codes, and the
plaintext of secured payloads are never emitted unless the application
enables the `dangerous-key-logging` feature, which is off by default and
warns at compile time.

## Reporting vulnerabilities

See `SECURITY.md`.
