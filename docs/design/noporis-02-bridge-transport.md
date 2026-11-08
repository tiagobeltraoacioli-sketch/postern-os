<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs -->

# NoporIS 02 — Bridge transport, consent protocol, kill-switch & audit

**Architect A5 · NoporIS.** Reference-prototype / DESIGN. **UNAUDITED — certifies
nothing.** This document specifies the *mechanism* that moves a consented item
across the NoporIS bridge, the consent protocol that authorizes each crossing,
the kill-switch that slams the span shut, and the tamper-evident audit ledger
that makes exfiltration provable after the fact.

> ## ⚠ HONESTY HEADER — carried on every surface below
>
> - **The Google-Play persona is the LESS-PRIVATE side, by construction.** It runs
>   GMS and **phones home to Google**. NoporIS sells **separation + convenience,
>   not privacy on that side**, and it never claims otherwise.
> - **Default-SAFE.** Nothing crosses unless a live, explicit consent record
>   authorizes **that item** in **that direction**, right now. A missing /
>   unparseable / partial state is full-deny.
> - **Two crypto worlds, said plainly.** The near (Clean) side's signing is
>   **Postern's post-quantum-aware** stack (the PQ-hybrid pairing channel,
>   ML-KEM-1024‖X25519). The Google side is **classical**. **Harvest-now,
>   decrypt-later applies to anything captured on the Google side** — treat every
>   Google-side crossing as recorded in the clear for a future adversary.
> - **Userland, not a kernel boundary.** Enforcement here is
>   `EnforcementMode::ByConstruction` — an in-process check. Only the
>   managed-profile storage/process split is a `KernelBoundary`, and that is
>   Android's, not ours. **A rooted / kernel-compromised host defeats every
>   boundary in this document.**
> - **App on stock Android — NEVER "Postern OS."** Respects Google/Android
>   licenses: no GMS redistribution (the user brings their own Google install),
>   no SafetyNet/Play-Integrity circumvention (honest labelling instead), Android
>   & Google Play named nominatively only. The guardian is **Yagabona**. The coin
>   (BLCH) is not a security and buys no software.

---

## 0. Scope & relationship to the fleet

NoporIS is the guarded **bridge** (the Kalinov crossing); **Porog** (A3/A4;
`apps/izbushka` + the stock-Android managed-profile container) is the guarded
**door**. This document (A5) owns the **transport, consent protocol, kill-switch,
and audit** — *how a consented item actually moves*, and how each movement is
authorized, cut, and logged.

- **A4** defines the two personas and the NoporIS↔Porog relationship. We consume
  the persona labels (`Persona::Clean`, `Persona::GooglePlay`) as **derived from
  the pairing**, never from a requester-controlled field.
- **A3** owns Porog's cross-profile enforcement side. NoporIS **drives** it: we
  publish the **state-file contract** (§4.3) that Porog reads to know whether the
  span is up and which crossings are lent. NoporIS is the writer; Porog is a
  read-only consumer.

This design **composes existing NoporIS code through public APIs** and adds only
the two net-new pieces the current scaffold lacks:

1. a **signed, per-item, per-direction consent record** (new
   `consent_record.rs`), and
2. a **tamper-evident crossing ledger** (new `audit.rs`) over the house
   `postern-trail` crate.

Everything else — the crossing envelope, replay guard, capability set,
deny-by-default gate, and bridge kill-switch — **already exists** and is reused
verbatim.

### What already exists (reused, not re-invented)

| Piece | Where | Reused as |
|---|---|---|
| Crossing envelope + `MAX_CROSSING_BYTES` + `crossing_session_id()` | `apps/noporis-bridge-glue/src/crossing.rs` | the wire item |
| `CrossingSender` / `CrossingReceiver` over PQ pairing `Channel`+`Transport` | `apps/noporis-bridge-glue/src/bridge.rs` | the transport driver |
| `CrossingGuard` (session/counter/nonce, fail-closed) | `apps/noporis-bridge-glue/src/crossing.rs` | in-flight replay guard |
| `GateConsent` seam + deny-by-default `ReferenceGate` | `apps/noporis-bridge-glue/src/consent.rs` | far-side authority |
| `Capability` (clipboard/files/mic/camera/location) + `tier()` | `apps/noporis-bridge-glue/src/capability.rs` | the five bridges |
| `CapabilityGrant` (near-side lever, time-boxed, revocable) | `apps/noporis-bridge-glue/src/grant.rs` | near-side consent |
| Gate state file + `normalize()` trust boundary | `apps/noporis-gate/gate-store.mjs`, `gate-state.schema.json` | persisted consent posture |
| `BridgeKillSwitch` (`ByConstruction`, holds no wallet/pairing) | `apps/noporis-signer-glue/src/killswitch.rs` | span cut |
| Hash-chained SHAKE-256 append-only trail | `crates/postern-trail` | audit ledger substrate |

---

## 1. Transport primitive — what carries a consented item

**Decision: a single bound cross-profile *broker service* with exactly one
method, driven by an explicit user gesture, carrying the existing sealed crossing
envelope. No content-provider URI grants, no implicit intents, no ambient
clipboard sync.**

### 1.1 On-device carrier

Android permits **one managed profile per user**, which maps 1:1 onto the two
NoporIS worlds:

- **Clean side** = the managed profile (Porog's container; de-Googled, wallet).
- **Google-Play side** = the primary/personal profile with GMS.

The only channel between profiles that an unprivileged app controls is a
**bound cross-profile service** (the AndroidX *Connected Apps* pattern: a
`@CrossProfile`-annotated service the DPC-provisioned app on each side binds to).
NoporIS uses **exactly one** such service —
`labs.postern.persona.bridge.CrossProfileBrokerService` — with a single IPC
method:

```
deliverCrossing(sealedFrame: ByteArray): DeliveryReceipt
```

Rationale for the minimal surface:

- **`sealedFrame` is opaque.** It is the bytes of a `postern_pairing::Frame`
  wrapping a `CrossingRequest` (AEAD-sealed, per-direction counter, session AAD).
  The broker service **cannot read the payload** — it is a dumb bearer. Authority
  lives in the pairing channel + the gate, not in the IPC boundary.
- **No `ContentProvider` cross-profile URI grants.** Those create ambient,
  hard-to-audit read channels. We refuse them: every item is a discrete,
  logged `deliverCrossing` call.
- **No implicit `Intent` broadcast.** The service is explicitly bound by package;
  a crossing is a method call, not a fan-out.
- **Explicit user action anchors every crossing.** The near side only calls
  `send_crossing` after the user threw the lever *and* (for the higher-tier
  caps) performed the per-crossing gesture — see §2.

### 1.2 Off-device model (what is unit-testable today)

The `bridge.rs` transport is generic over `postern_pairing::Transport`. On device
`Transport::send/recv` is backed by the broker service's `deliverCrossing`; in
tests it is an in-memory pipe. **The entire consent→cross→audit→kill flow is
therefore exercisable off-device** (`cargo test`) with the real crypto and real
gate logic — only the last-inch IPC binding is Android-specific.

```
 Clean profile (managed)                         Google-Play profile (primary)
 ───────────────────────                         ─────────────────────────────
 user throws lever  ──► signed ConsentRecord (§2)
 send_crossing(cap, payload, dir)
   grant check (near, live?)  ─┐
   seal into pairing Channel   │  Frame bytes
   AUDIT: append "sent"        │  via CrossProfileBrokerService.deliverCrossing()
                               └────────────────► receive_crossing()
                                                    open_frame (channel replay)
                                                    CrossingGuard (nonce/ctr/session)
                                                    ConsentRecord verify (sig + dir + item + fresh)
                                                    GateConsent.decide(cap)  ← deny-by-default
                                                    killswitch check          ← fail-closed
                                                    Allow ⇒ deliver (zeroizing)
                                                    AUDIT: append "delivered"/"denied(reason)"
```

---

## 2. Consent protocol — signed, per-item, per-direction

**Decision: every crossing is authorized by a `ConsentRecord` — a signed,
per-capability, per-direction, time-boxed token created by a user gesture,
stored beside the gate state, verified before every crossing, and revocable.**

This *upgrades* the current model. Today there are two composed checks: the
near-side `CapabilityGrant` (a lever) and the far-side `GateConsent` verdict (a
toggle in `gate-state.json`). Neither is **signed** and neither pins a
**direction** cryptographically. The `ConsentRecord` binds both into one
attributable, tamper-evident authorization.

### 2.1 Consent record schema (new `apps/noporis-bridge-glue/src/consent_record.rs`)

```jsonc
{
  "schema": "postern.noporis.consent-record",
  "v": 1,
  "id":         "<32-byte hex — SHAKE-256 of the canonical body>",
  "capability": "clipboard | files | mic | camera | location",
  "direction":  { "from": "Clean|GooglePlay", "to": "Clean|GooglePlay" },
  "session_id": "<16-byte hex — the crossing session id (crossing_session_id())>",
  "peer_device":"<peer pin from the PairingRecord — NOT requester-supplied>",
  "scope":      "single | session",   // single = one crossing then dead; session = until boot/revoke
  "issued_at":  "2026-07-13T00:00:00Z",
  "expires_at": "2026-07-13T00:05:00Z",
  "gesture":    "toggle | per-crossing-tap",  // the user action that minted it
  "sig": {
    "alg": "postern-pq-hybrid",       // NEAR-SIDE crypto: PQ-aware. Signed by the Clean-side signer.
    "value": "<signature over the canonical body, id excluded>"
  }
}
```

Rules (all fail-closed):

- **Per-item, per-direction.** A record authorizes exactly one `capability` in
  exactly one `{from→to}`. Clipboard-to-Google does **not** authorize
  clipboard-from-Google, nor files-to-Google.
- **Direction is derived, then pinned.** `from`/`to` come from *which paired peer
  the frame is on* (`persona.rs`), and the signature commits to them. A
  compromised far side cannot forge a record for the other direction because it
  cannot produce the near-side signature.
- **Signed by the near side only.** The `sig` is produced by the Clean-side
  Postern signer (PQ-aware). The Google side can **request** but never **mint**
  consent. This is the honest asymmetry: the private side is the authority.
- **Time-boxed.** `expires_at` is mandatory; an expired record is *never given*.
  `single` scope additionally dies after the first accepted crossing (burned by
  its `id` in the crossing guard's seen-set).
- **`id` = SHAKE-256(canonical body without `id`/`sig`)** — house canonical form
  (RFC-8785-in-spirit, per `postern-trail`). The `id` is what the audit ledger
  references, so an audit entry points at the exact authorization used.

### 2.2 Creation — the user gesture

1. The user enters the bridge once per scope by accepting the honest disclosure
   in `apps/noporis-gate` (`consent.accepted = true`). This does **not** open any
   crossing.
2. To lend a capability, the user **throws that capability's lever** in the
   NoporIS UI (`openCrossing(cap)` in `gate-store.mjs`). For `SingleTap`-tier
   caps (`clipboard`, `files`) the lever is the gesture. For the higher-tier
   caps (`mic`, `camera`, `location` — `ConsequenceTier` per `capability.tier()`)
   a **per-crossing tap** is additionally required at send time.
3. Throwing the lever calls the Clean-side signer to **mint a `ConsentRecord`**
   for `{cap, from→to, scope, expiry}` and writes it to the consent store.

No blanket "open all." Each record is one lever, one direction. Anti-round-up:
nothing crosses that the user did not hand across.

### 2.3 Storage

- **Consent posture** (which levers are up, kill-switch, wallet-preserved
  invariant): `gate-state.json` — the existing v1 schema, canonical path
  `/var/lib/postern/noporis-gate/state.json` (0600, root-owned).
- **Signed consent records**: append-only alongside, at
  `/var/lib/postern/noporis-gate/consent-records.jsonl`. Records are looked up by
  `{capability, direction}`; the newest live one wins. A revoked/expired record
  is retained (for audit) but never satisfies a crossing.

### 2.4 Check — before every crossing

The receiver's fail-closed order (extends the existing `receive_crossing`):

1. Pairing channel `open_frame` (AEAD + channel counter/session/direction guard).
2. `CrossingGuard.check` (session, monotonic counter, fresh nonce) — no mutation.
3. **`ConsentRecord` verify**: a live (non-expired, non-revoked) record exists
   for `{req.capability, from→to}`, its `sig` verifies against the pinned
   near-side key, its `session_id` matches, and (for `single` scope) its `id` is
   unburned.
4. `GateConsent.decide(cap, from, to)` — deny-by-default toggle still `open`.
5. `BridgeKillSwitch` disengaged (§3).

Only if **all** pass does the receiver `commit` the guard and deliver the
zeroizing payload. **Any** failure delivers nothing and is logged as a denial
(§4).

### 2.5 Revoke

Four revocation surfaces, all collapsing to "never given":

- `revoke_lane(cap)` — near-side grant dropped, and the matching `ConsentRecord`
  marked revoked.
- `closeCrossing(cap)` — gate toggle back to deny.
- `withdrawConsent()` — leaves the bridge entirely; all records for the session
  die.
- **Kill-switch** (§3) — revokes *all* outstanding records at once.

Revocation is monotonic and immediate: the next crossing check fails closed.

---

## 3. Kill-switch — slam the span shut

**Decision: reuse `BridgeKillSwitch` (userland, `ByConstruction`), extend
`engage()` to (a) revoke all outstanding consent records, (b) clear in-flight
state, and (c) write the state-file contract Porog reads. Never touches the
sealed wallet.**

### 3.1 Semantics

Engaging the kill-switch, atomically:

1. **Closes the bridge.** `killSwitch.engaged = true` in `gate-state.json`;
   `bridge_decision()` returns `Deny` for every subsequent crossing; the switch
   **will not lapse on a timer** — reopening is an explicit `disengage()`.
2. **Revokes outstanding consents.** Every live `ConsentRecord` is marked
   revoked; every near-side `CapabilityGrant` is dropped; every gate toggle is
   forced to deny (`revokeAllCrossings()`).
3. **Clears in-flight state.** Any `CrossedPayload` in RAM is zeroized on drop
   (already the case via `zeroize::Zeroizing`); the `CrossingReceiver` is
   released so its `CrossingGuard` nonce-set and counter are dropped; the broker
   service unbinds so no `deliverCrossing` can be in flight.
4. **Preserves the sealed wallet — invariant.** `sealedWallet.preserved` is
   pinned `true` and is never read from input; no kill-switch path can clear it.
   The door (Porog) and the keys survive the span dropping. `BridgeKillSwitch`
   holds no wallet state and no `PairingRecord` **by construction**, so it
   *cannot* destroy either.

### 3.2 State-file contract that Porog (A3) reads

NoporIS is the **sole writer**; Porog is a **read-only consumer**. Two files,
both consumed elsewhere in the tree, so we honor their existing contracts:

1. **`gate-state.json`** (canonical `/var/lib/postern/noporis-gate/state.json`,
   0600 root) — the full v1 schema. Porog/A3 reads `killSwitch.engaged`,
   `consent.accepted`, and the per-capability `crossings.*.open` to know which
   cross-profile plumbing to expose. **Missing / unparseable / unknown-version →
   full-deny + not-consented** (the `normalize()` trust boundary).

2. **`sloboda-bridge.state`** (canonical `/run/postern/consent/sloboda-bridge.state`)
   — the tiny toggle file `apps/sloboda`'s wrapper already treats as
   **read-only**, where the bridge is enabled **only if line 1 is exactly
   `enabled`**. NoporIS writes this as a **derived projection** of the gate state:

   ```
   line 1: "enabled"   iff  consent.accepted && !killSwitch.engaged && any crossing open
           "disabled"  otherwise   (default, and on kill-switch)
   ```

   Engaging the kill-switch writes `disabled` *before* returning, so a consumer
   polling the toggle sees the span down atomically. This is the file Porog's
   enforcement side watches to slam its cross-profile controls shut.

Write discipline: write to a temp file in the same dir, `fsync`, `rename()` over
the target (atomic replace) so a reader never sees a half-written state.

---

## 4. Tamper-evident audit ledger

**Decision: every crossing decision — sent, delivered, and denied — is one record
appended to a hash-chained, append-only `postern-trail` ledger (SHAKE-256 house
style). Exfiltration is provable after the fact by `verify_chain`.**

### 4.1 Substrate — the house trail

We do **not** invent a chain. We add a content type to `crates/postern-trail`,
exactly as `ezekiel1` and `yagabona` do:

```rust
// apps/noporis-bridge-glue/src/audit.rs
pub type CrossingTrail = postern_trail::Trail<CrossingRecord>;

#[derive(Serialize, Deserialize)]
pub struct CrossingRecord {          // content only; the trail owns v/prev_hash/hash
    pub ts: String,                  // RFC-3339
    pub event: String,               // "sent" | "delivered" | "denied"
    pub capability: String,          // clipboard|files|mic|camera|location
    pub from: String,                // "Clean" | "GooglePlay"
    pub to: String,
    pub tier: String,                // SingleTap | ... (from capability.tier())
    pub decision: String,            // "allow" | "deny"
    pub reason: Option<String>,      // DenyReason on a denial
    pub consent_id: Option<String>,  // the ConsentRecord.id that authorized it
    pub session_id: String,          // crossing session (hex)
    pub counter: u64,                // monotonic per-session
    pub nonce: String,               // per-crossing nonce (hex)
    pub payload_len: usize,          // bytes that crossed — SIZE only
    pub payload_digest: String,      // SHA-256 of the payload — NOT the payload
    pub killswitch: bool,            // engaged at decision time
}
```

Chain: `hash = SHAKE-256( prev_hash_bytes ‖ canonical_json({content, prev_hash, v}) )`,
first `prev_hash = GENESIS`, `fsync`-per-append — all inherited from
`postern-trail`. **Tamper-evident, not tamper-proof**: the file owner can rewrite
the whole trail and recompute every hash; what `verify_chain` guarantees is that
a *partial* edit is caught, and `verify_chain_to_head` against a pinned head
catches truncation/rollback.

### 4.2 What is and is not logged

- **Logged on every attempt**: the *fact* of a crossing, its direction,
  capability, decision + reason, the authorizing `consent_id`, freshness metadata,
  payload **size** and **SHA-256 digest**, and the kill-switch state.
- **Never logged**: the payload bytes themselves. The digest lets you later prove
  *which* item crossed (match a suspect file against the digest) without the
  ledger itself becoming an exfiltration copy.
- **Honesty on the digest**: the payload SHA-256 is a **classical** hash of data
  that may have originated on the Google side — it is an integrity/attribution
  aid, not a confidentiality guarantee. Harvest-now-decrypt-later still applies to
  anything the Google side saw.

Both `allow` and `deny` are logged, so a *refused* exfiltration attempt is as
provable as a successful one.

### 4.3 Location

`/var/lib/postern/noporis-gate/crossings.trail.jsonl` (0600, root-owned, same
dir as the gate state). A companion `verify` subcommand runs `verify_chain` and,
if a head is pinned (e.g. in the sealed base), `verify_chain_to_head`.

---

## 5. Files & components

| Path | Status | Role |
|---|---|---|
| `apps/noporis-bridge-glue/src/consent_record.rs` | **NEW** | signed per-item/per-direction `ConsentRecord` + verify/mint/revoke |
| `apps/noporis-bridge-glue/src/audit.rs` | **NEW** | `CrossingRecord` content + `CrossingTrail` wiring; append on send/deliver/deny |
| `apps/noporis-bridge-glue/src/bridge.rs` | edit | `send_crossing`/`receive_crossing` gain the consent-record check + audit append |
| `apps/noporis-bridge-glue/src/crossing.rs` | reuse | envelope + `CrossingGuard` (unchanged) |
| `apps/noporis-bridge-glue/src/consent.rs` | reuse | `GateConsent` seam + `ReferenceGate` (unchanged) |
| `apps/noporis-bridge-glue/Cargo.toml` | edit | add `postern-trail`, `sha2` (already a dep) deps |
| `apps/noporis-gate/gate-state.schema.json` | reuse | consent posture + kill-switch + wallet invariant (v1) |
| `apps/noporis-gate/gate-store.mjs` | edit | mint/emit the `sloboda-bridge.state` projection on state change |
| `apps/noporis-signer-glue/src/killswitch.rs` | edit | `engage()` also revokes records + writes both state files |
| `android-bridge/persona/.../bridge/CrossProfileBrokerService.kt` | **NEW** | the single-method cross-profile bearer (on-device) |
| `crates/postern-trail` | reuse | SHAKE-256 hash-chained append-only substrate |
| `/var/lib/postern/noporis-gate/{state.json,consent-records.jsonl,crossings.trail.jsonl}` | runtime | consent posture · signed records · audit ledger |
| `/run/postern/consent/sloboda-bridge.state` | runtime | derived toggle Porog/sloboda reads |

---

## 6. Toolchain & infra

- **Rust** (workspace crates, `#![forbid(unsafe_code)]`): `cargo test`,
  `cargo clippy`. Deps: `postern-pairing`, `postern-signer-protocol`,
  `postern-trail`, `postern-policy`, `sha2`, `sha3` (via trail), `zeroize`,
  `serde`/`serde_json`. RustCrypto only; no network once cached.
- **Node** (dependency-free): `gate-store.mjs` + `test-store.mjs`
  (`node test-store.mjs`) for the state kernel and the `sloboda-bridge.state`
  projection; JSON-Schema draft-07 for the state file.
- **Kotlin/AndroidX** (on-device only): the `@CrossProfile` broker service, built
  in the existing `android-bridge/persona` Gradle project; instrumented on a
  **work-profile emulator** (an AVD provisioned with a managed profile) or a real
  dual-profile device.
- **CI**: `cargo test` + `node test-store.mjs` + `shellcheck` run off-device;
  the Kotlin instrumented tests are gated to a device/emulator lane.

---

## 7. Functional-proof test — "one item crosses, then the switch blocks the next"

The canonical proof, **off-device** (`cargo test` in `apps/noporis-bridge-glue`,
in-memory `Transport`, real pairing crypto + real gate + real trail):

1. **Consent** — accept the bridge; throw the `clipboard` lever Clean→GooglePlay;
   assert a signed `ConsentRecord` is minted and verifies.
2. **One item crosses** — `send_crossing(Clipboard, …)` then `receive_crossing`
   returns the delivered `CrossedPayload`; assert bytes match.
3. **Audit entry appears** — open the `CrossingTrail`; assert exactly two new
   records (`sent`, `delivered`), the `delivered` one has
   `decision == "allow"`, the right `consent_id`, and a `payload_digest` equal to
   `SHA-256(payload)`; assert `verify_chain` passes.
4. **Kill-switch blocks the next** — `engage()`; assert `sloboda-bridge.state`
   line 1 is now `disabled`, every `ConsentRecord` is revoked, and the next
   `send_crossing`/`receive_crossing` fails closed (`KillSwitchEngaged`); assert
   a third trail record (`denied`, reason `KillSwitchEngaged`) is appended and
   `verify_chain` still passes.
5. **Tamper detection** — flip one byte in an earlier trail line; assert
   `verify_chain` now returns `HashMismatch`/`BrokenLink` at that line.
6. **Wallet invariant** — assert `sealedWallet.preserved` is still `true` after
   the kill-switch.

**On-device (UNTESTED until run)** — what only a work-profile emulator/device can
confirm: that `CrossProfileBrokerService` actually binds across the managed↔primary
profile split; that `deliverCrossing` carries the sealed frame with no ambient
side channel; that unbinding on kill-switch is immediate; that Porog's
enforcement side observes the `sloboda-bridge.state` flip and closes its
cross-profile controls; and the honest Play-Integrity reality on the Google side.

---

## 8. Honesty constraints (non-negotiable rails)

1. **Google side = less private, classical crypto, harvest-now-decrypt-later.**
   Every surface naming the Google persona says so; the audit digest is classical
   and confidentiality-free.
2. **Default-SAFE / deny-by-default.** No item crosses without a live, signed,
   per-item, per-direction consent record + gate `Allow` + disengaged switch.
   Missing/garbage state = full-deny.
3. **Kill-switch slams shut and never destroys the sealed wallet.**
4. **Userland, `ByConstruction`, not a kernel boundary; a rooted host defeats
   it.**
5. **Respects Google/Android licenses** — no GMS redistribution, no Integrity
   circumvention, nominative naming only.
6. **Reference-prototype, UNAUDITED. UNTESTED on device.** The coin is not a
   security. Personal use is free. Not legal advice. NoporIS/Nopor mark pending
   trademark clearance.

---

## 9. Phased dev task-list

**Phase 1 — Consent record (off-device, unit-testable).**
`consent_record.rs`: schema, canonical `id`, near-side signature verify, mint,
revoke, expiry, `single`-scope burn. Tests: forged direction rejected, expired
rejected, wrong-key rejected.

**Phase 2 — Audit ledger (off-device).** `audit.rs`: `CrossingRecord` +
`CrossingTrail` over `postern-trail`; append helpers for send/deliver/deny; digest
= SHA-256, never the bytes. Tests: two records on a crossing, `verify_chain`,
`verify_chain_to_head`, single-byte tamper detected.

**Phase 3 — Wire into the bridge (off-device).** Extend `send_crossing` /
`receive_crossing` with the consent-record check (step 3 of §2.4) and the audit
appends. The full §7 functional-proof test goes green here.

**Phase 4 — Kill-switch fan-out (off-device).** Extend `engage()` to revoke all
records + write both state files atomically (`rename()`); `gate-store.mjs` emits
the `sloboda-bridge.state` projection. Tests: engage → `disabled`, all revoked,
next crossing denied, wallet preserved.

**Phase 5 — On-device transport (needs emulator/device).**
`CrossProfileBrokerService` (single `deliverCrossing`); provision a work-profile
AVD; instrumented test that a sealed frame crosses and that unbind-on-kill is
immediate; confirm Porog reads the state files.

**Phase 6 — Honest labelling + docs.** Surface the less-private / classical /
HNDL / userland rails in the NoporIS UI and receipts; wire the `verify` subcommand
for the ledger; update `apps/noporis-*/README` cross-references. Hardware/Integrity
realities remain UNTESTED until a real dual-profile device run.
