<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# PRIVACY-CROSSING — what leaves the attested profile (NoporIS + Porog)

**Status: DESIGN ONLY · UNAUDITED.** The Rust half is host-proven (commands below run
on macOS today); the Kotlin/on-device half is `[BOX] UNTESTED-until-VM`. This is a
metadata-minimization *audit + enumeration*, not a security guarantee. No claim here
promotes either app above its honest tier: Porog is a **key-attested device** (it
attests the phone's device key), **not** a measured-boot workspace and **never**
"Postern OS"; NoporIS is an ordinary app on stock Android. A rooted/kernel-compromised
host defeats both boundaries.

This document exists because "the broker is a dumb bearer" and "audit is by digest,
never bytes" were asserted in prose across many files but never enumerated in **one
place** with the exact leave-set. This is that place.

---

## 0. The two crossings

| Bridge | Boundary crossed | Bearer | Decision authority |
|---|---|---|---|
| **NoporIS** | persona ↔ persona (clean managed profile ↔ Google-Play profile) on one handset | `CrossProfileBrokerService.deliverCrossing(sealedFrame)` — one bound cross-profile service, one method | the pairing **Channel** + **gate** + signed **ConsentRecord**, on the far side (`apps/noporis-bridge-glue`) — never the IPC boundary |
| **Porog** | personal (user 0) ↔ managed work profile the DPC owns | Android framework: cross-profile intent filters + cross-profile package allowlist + copy/paste user-restriction | the pure, host-tested reconcile kernel (`apps/porog-crossprofile/reconcile-kernel.mjs`), ported once into `dpc/CrossProfileReconciler.decide()` and applied by that same `dpc/CrossProfileReconciler` |

Both bridges are **fail-closed**: absent/corrupt/unknown input ⇒ full-deny; the only
self-write either enforcement side may perform is toward *more closed*.

---

## 1. NoporIS — the exact leave-set across the profile split

### 1a. What crosses IN (the request)
- **Exactly one value:** an opaque `sealedFrame: ByteArray` — the bytes of a
  `postern_pairing::Frame` wrapping a `CrossingRequest` (AEAD-sealed, per-direction
  counter, session AAD). The broker **cannot read it** — it holds no keys.
- **Bounded:** `CrossingBearerPolicy.MAX_SEALED_FRAME_BYTES = 64 KiB` (a coarse DoS
  ceiling on the *sealed* frame). The authoritative correctness ceiling is the
  *opened* payload's `MAX_CROSSING_BYTES = 16 KiB`, enforced downstream in
  `crossing.rs`. The bearer ceiling is a deliberate over-approximation and must never
  drop below the payload ceiling (pinned by D2 in `crossing.rs` + `CrossingBearerPolicyTest`).
- **No ambient channels:** the service declares **no `<provider>`**; `rejectUriGrant`
  hard-fails any `content://` / `Uri` / `FLAG_GRANT_*`, and `rejectImplicitBind`
  hard-fails any implicit or action-bearing bind. A crossing is a discrete, logged
  method call — never a URI grant, never an implicit broadcast.

### 1b. What crosses OUT (the return)
- **Exactly one value:** `DeliveryReceipt { borne: Boolean, frameLen: Int, reason: String? }`
  — the *fact* and *size* of a bearing attempt, plus an honest refusal reason.
  **Never** the payload; **never** anything read out of the sealed frame (the bearer
  cannot read it). `borne == true` means only "carried", **not** "authorised".

### 1c. What the audit ledger records (`apps/noporis-bridge-glue/src/audit.rs`)
One append-only, SHAKE-256 hash-chained `CrossingRecord` per send / deliver / deny:

| Field | Content | Privacy note |
|---|---|---|
| `ts` | RFC-3339 timestamp | when, not what |
| `event` | `sent` / `delivered` / `denied` | the outcome |
| `capability` | stable machine key (e.g. `clipboard`) | *which lever*, not the data |
| `from` / `to` | persona label | which side, not identity/PII |
| `session_id` | hex of 16-byte session id | ties entries to a paired session |
| `counter` | per-session monotonic `u64` | ordering / replay detection |
| `payload_len` | size in bytes | attribution, not content |
| `payload_sha256` | lowercase-hex SHA-256 of payload | attribution (which blob crossed / crossed twice) — **not** confidentiality, not a secret |
| `reason` | honest deny reason (deny entries only) | why refused |

**The opaque payload bytes are never written to the trail.** The ledger is a local
device record — never telemetry, never leaves the device. It is *tamper-evident, not
tamper-proof*: `postern_trail::verify_chain` catches any partial edit; the machine
owner can always rewrite the whole file.

---

## 2. Porog — the exact leave-set across the profile boundary

### 2a. What the DPC can and CANNOT see
Porog's DPC governs **only the managed profile it owns**. Cross-profile data movement
is **Android-framework-mediated** (a cross-profile intent filter resolves a share; the
package allowlist backs a standing cap; the copy/paste restriction gates the clipboard)
and happens **after** a grant, **below the DPC's visibility**. The DPC sets the *policy
shape*; the framework carries the *content*. So:

- The reconciler **cannot** log the individual file the user then shares, each
  clipboard paste, or each contact read — those are mediated by the OS after the grant.
- The reconciler is a **pure reader** of `files/porog-gate/state.json`
  (managed-profile-private, FBE-encrypted). It **never writes grant state**.
- It **cannot un-send** bytes already copied — closing a crossing stops FUTURE flows
  and revokes LIVE grants only.

### 2b. What the on-device audit log records (`dpc/CrossProfileAuditLog.kt`)
Local-only, append-only JSONL, FBE app-private dir, bounded by truncation
(`MAX_LINES = 2000`). **No network, ever.** One entry per policy **transition**, drawn
only from the canonical `CrossProfileDirectives.Directives` the reconciler applied:

| Field | Content |
|---|---|
| `ts` | UTC timestamp |
| `trigger` | `PROVISIONING` / `BOOT` / `STATE_CHANGE` / `KILL_SWITCH` |
| `open` / `cleared` / `reason` | the fail-closed verdict |
| `intentFilters[]` | `{capability, direction}` per installed filter |
| `crossProfilePackages[]` | `{capability, direction}` per standing-cap allowlist entry |
| `copyPasteDisallowed` | clipboard posture |
| `clipboardDirection` | declared clipboard direction (advisory; OS copy/paste is directionless) |

It logs **that the boundary was configured to allow X, and when** — the *policy shape
over time*. It records **no** filename, **no** clipboard value, **no** contact, **no**
byte that crossed. (Post-dedupe the summary is sourced from the single authoritative
`CrossProfileDirectives` decision — see §4.)

---

## 3. The leave-set, minimized (the one table)

| Surface | Leaves the profile | Provably NOT in the leave-set |
|---|---|---|
| NoporIS request | one opaque, size-bounded sealed frame | plaintext payload, capability decision, any grant, URI grants, implicit intents |
| NoporIS reply | `borne`, `frameLen`, optional refusal `reason` | payload, anything read from the frame |
| NoporIS audit | ts, event, capability key, persona labels, session id, counter, len, digest, deny reason | payload bytes |
| Porog framework crossing | only what the granted cross-profile filter / allowlist / clipboard policy carries, OS-mediated | anything the DPC could log per-item (it cannot see individual crossed content) |
| Porog audit | ts, trigger, verdict, {capability, direction} per directive, clipboard posture | filename, clipboard value, contact, any crossed byte; never telemetry |

**PII / content minimization:** neither audit surface stores user content or an
identity. NoporIS keeps a digest+len (attribution, reversible only by already holding
the blob); Porog keeps only capability+direction policy metadata.

---

## 4. Invariants + how each is proven

**Host-runnable now (Rust, `apps/noporis-bridge-glue`):**
- `delivered_crossing_is_audited_by_digest_never_bytes` (`src/lib.rs:382`) — both sides
  log by digest, the digests match, and the ledger is hash-chain-verified. The
  `CrossingRecord` struct (`src/audit.rs`) has **no** payload field by construction.
- `gate_denied_crossing_is_audited_with_the_reason` (`src/lib.rs`) — a deny records the
  honest reason, still by digest.
- Proof: `cd apps/noporis-bridge-glue && cargo test` (protect ≥124). *(D2 owns any
  new Rust-side digest-only assertion for added audit surface.)*

**`[BOX] UNTESTED-until-VM` (Kotlin, host-shaped, box-run):**
- A `CrossProfileAuditLog` host unit test mirroring the Rust stance — assert a recorded
  entry contains capability/direction/verdict **shape** and **no** payload/filename
  field — is the Kotlin mirror of the invariant above. It is host-shaped (JVM, no
  Android SDK needed for the pure JSONL assertion) but is proven only on the box via
  `./gradlew :app:testDebugUnitTest`. Owning-test authorship coordinates with D2/D3;
  D5's dedupe made this assertable against **one** `Directives` shape.

**Dedupe that de-risks this audit (D5):** the Porog decision was previously split across
two same-named Kotlin ports. The redundant `crossprofile/CrossProfileReconciler` port was
retired, leaving **one** canonical port — `dpc/CrossProfileReconciler` (427 lines), whose
`decide()` is pinned to the single kernel by committed golden vectors
(`apps/porog-crossprofile/golden-vectors.json`) and a `[BOX]` JVM parity test
(`CrossProfileReconcilerParityTest`). The audit now records that one decision, so there is
one decision authority and one shape to assert against — no drift between "what was decided"
and "what was logged". *(No `GateStateReconciler` type exists; an earlier draft of this doc
named one — that rename never happened and the reference is removed.)*

---

## 5. Honesty labels (keep verbatim)
- Porog attests the **phone** (key-attested device), **not** the workspace — not a
  measured-boot workspace, never a Postern Seal, never "Postern OS."
- The audit ledgers are **local device records, never telemetry**; they are
  tamper-evident, **not** tamper-proof.
- Every on-device / cross-profile-bind claim here is `UNTESTED-until-VM` and labeled as
  such — never presented as a host pass.
