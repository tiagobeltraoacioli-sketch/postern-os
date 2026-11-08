<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- Copyright (c) Postern Labs and Postern community contributors -->

# The OS Portal — security & privacy (the trust boundary)

**Status: DESIGN CONCEPT ONLY. Nothing in this document is built, deployed, or
audited.** This is Design PMO 2's pass on the same *new* product
`docs/os-portal/01-architecture.md` (PMO 1) defines: a license-gated,
consent-gated desktop portal (working name **Novosel**, proposed only, pending
trademark clearance) that uses an AI agent to install Windows, Ubuntu, RedHat,
and other operating systems on a client's behalf. PMO 1 owns the
architecture — the brain/hands (Planner/Executor) split, the three deployment
shapes, the fixed executor verb set, the `portal-gate` consent tier sketch —
and explicitly handed the deep trust/privacy threat model to this document.
This document does not re-derive PMO 1's architecture; it red-teams it,
deepens the parts that are this dimension's job, and answers PMO 1's open
questions §5.1, §5.2, §5.3, §5.4, §5.5, and §5.9 where they are security/privacy
questions.

Same discipline as every other design doc in this tree: `designed ≠ built`,
`written ≠ audited`, `verifiable ≠ verified` (this document's own addition to
that family — see §6). Nothing here is a security control until it is code,
reviewed, and run.

---

## 0 · The one-sentence claim, and why it needs to be provable, not promised

**The claim this product wants to make:** *"Postern cannot see your data
during the install, the AI agent only ever handles install *commands*, not
your files, and you don't have to take our word for it — you can check."*

That claim is only honest if it is **architectural** (the data structurally
cannot reach a party, because no code path carries it there) rather than
**operational** ("we promise not to log it"). Every design decision below is
chosen because it makes the claim checkable by the client or a third-party
auditor, not because it is convenient. Where a check requires the client to
actually *run* it, that is stated plainly (§6) — an unrun check is a promise,
not a proof, for the client who skipped it.

---

## 1 · Threat model — adversaries, capabilities, and boundaries

| Adversary | What a naive design would leak | What it CAN do here | What it CANNOT do here | Primary mitigation |
|---|---|---|---|---|
| **A rogue or prompt-injected Planner** (the AI agent's reasoning half) | Steer the install toward wiping the wrong disk, installing a backdoored package, or smuggling data out via a "helpful" network call | Draft a malicious *plan* (typed data); request a `network-fetch` of an attacker URL; request any verb | **Cannot execute anything.** No shell, no raw block-device handle, no signing key. Cannot forge an `InstallConsentRecord` (§3) or an `InstallGrant` (§4) — no key material. Cannot see raw client files/credentials — the schema it's shown is an allowlist (§2.2), not a redaction-after-the-fact. Cannot fetch an unlisted host (Executor enforces the allowlist, not the Planner). | Brain/hands split (PMO 1 §2.1) + fixed executor verb set + per-instance signed consent (§3) + digest-pinned image manifest |
| **A malicious OS image / supply chain** (compromised mirror, backdoored ISO) | Get written to disk as if genuine | Exist, be hosted, be linked | Be silently substituted for a client who opted into digest pinning — the Executor's `apply-image` verb checks the image's hash against a signed manifest **before consuming it**, independent of what the Planner said | Signed image-manifest allowlist, checked by the deterministic Executor, never the Planner (§1 honest limit: only as strong as the vendor's own publishing integrity, §6) |
| **Postern-the-company** | See client files, credentials, hardware identity, browsing history of the install | Publish the vendor license root key; publish the Executor's expected `image_digest`/`os_roothash`; optionally operate a relay | **Cannot read client data by default** — not "chooses not to," structurally absent from the data path in the recommended deployment (Tier B, §2.4). Even in the optional Tier C (Postern-operated relay), only ever receives the same allowlist-schema, tripwire-checked plan state the Planner would get, inside an attested confidential VM the client verifies before sending anything. Never receives the local audit trail (device-local, matches `postern-trail`/Yagabona's zero-telemetry stance) and never holds the operator's local `ConsentAuthority` key | Data-never-in-the-path by default; attested relay as an opt-in, verified exception |
| **The AI model provider** (if a cloud model is used) | Same as above, plus training-data retention risk | Receive the redacted install-plan state over whichever tier the operator chose | Receive file contents, credentials, Wi-Fi passwords, filenames, or raw error text (closed enum, never free text) — enforced by the allowlist schema **and** an independent outbound tripwire (§2.3) | Allowlist schema + tripwire, defense in depth |
| **A network attacker** (hostile Wi-Fi, on-path) | Read or tamper with plan traffic, substitute an OS image in transit | Observe encrypted traffic size/timing; attempt MITM | Read plaintext (key-committing AEAD, `crates/postern-core::aead`; sealed, optionally sender-authenticated drops, `crates/postern-courier`); substitute an image (digest pinning, independent of transport); forge a `ConsentRecord`/`InstallGrant` (asymmetric signatures never touch the wire in a form that can be replayed) | AEAD sealing + digest pinning + signature-bound tokens |
| **A compromised host** (the machine being provisioned, or the technician's driving machine) | Defeat every software boundary above it | Everything, if the boot/runtime environment the Executor runs from is itself already owned | Nothing is claimed to survive this. Mitigated only by running the Executor from a **separate, measured-boot** live/PXE environment verified *before the first privileged consent* — not eliminated | **Honest limit, not solved** — see §1.6 and §6 |

### 1.1 Detail: the compromised-host case is the hardest one, and the design does not pretend otherwise

If the Executor's own boot image is itself tampered with (backdoored USB
stick, compromised PXE server, Evil-Maid firmware implant), no control that
*runs inside that environment* can be trusted to report on itself honestly.
The only real defense is **verify before you trust it with a single
privileged consent**: the client checks the running image's measurement
*before* granting the first `InstallConsentRecord`, using the same
reproducible-build + measured-boot chain `os/ATTESTATION.md` already
documents (erofs + dm-verity + UKI, extended here to the portal's own
executor image, per PMO 1 §2.4a/§2.5). This pushes the trust anchor back one
more step — to the firmware/TPM chain of custody — which is exactly where
every other Postern bridge product (Porog, NoporIS, Waydroid) also bottoms
out, and exactly where `docs/design/bridge-trust-boundaries.md` refuses to
overclaim. This document keeps the same discipline: **a rooted or
firmware-compromised host defeats this boundary, like every other one in the
fleet.**

---

## 2 · The privacy architecture — where the agent runs, and how the claim stays provable

This section answers PMO 1's open question §5.1 ("remote-LLM brain vs.
no-phone-home doctrine") directly: **the answer is that "where the Planner
runs" and "what the Planner is ever shown" are two independent knobs, and
the second one is the one doing the real work.**

### 2.1 Two orthogonal levers, not one

A common mistake is to treat "run the model locally" as *the* privacy
control. It is not sufficient on its own: a fully on-device model that is
handed raw file contents and credentials is *more* private than a cloud
model handed the same thing, but neither is what this product promises.
Conversely, a cloud model that is architecturally *never shown* raw client
data is a stronger privacy design than a local model naively wired to see
everything, because "never shown" doesn't depend on trusting the runtime at
all. So the design separates:

- **(a) WHAT the Planner is ever allowed to see** — the *Install-Plan State*
  schema (§2.2) and the outbound tripwire (§2.3). This is the primary,
  always-on control, identical regardless of deployment tier.
- **(b) WHERE the Planner executes** — a client-selectable tier (§2.4),
  defense-in-depth on top of (a), and the knob that determines *who* could
  even theoretically see the (already-redacted) plan state.

### 2.2 What the Planner is ever shown: an allowlist, not a redaction

The Planner never receives a general-purpose view of the client's machine.
It receives a strictly-typed **Install-Plan State**, JSON-Schema validated
with the same `normalize()`-collapses-to-nothing idiom every consent-spine
schema in this repo already uses
(`apps/consent-contract/consent-spine.schema.json`,
`apps/noporis-gate/gate-state.schema.json`) — a field that isn't in the
schema cannot leak, by construction, because there is no code path that
serializes it in. This is an **allowlist**, deliberately, not a
redact-after-the-fact denylist: a denylist fails open on a field nobody
thought to ban yet; an allowlist fails closed on everything not explicitly
named.

Sketch (illustrative, not final — the field set is PMO 1/PMO 2's joint
design job before build):

```
InstallPlanState {
  target:   { classId, diskCount, diskSizeBuckets[], nicCount,
              hasDiscreteGpu, secureBootState, tpmPresent }
  os:       { vendor, product, version, channel }
  history:  [{ verb, outcome: "ok" | "error", errorClass }]   // errorClass
                                                                // is a CLOSED
                                                                // enum, never
                                                                // raw stderr —
                                                                // that's where
                                                                // paths/usernames
                                                                // leak
  intent:   { diskEncryption: bool, dualBoot: bool, ... }      // booleans/enums
                                                                // only, never
                                                                // free text
}
```

Explicitly **absent from the schema, forever, by design**: filenames, file
contents, usernames, disk *serials* (the human-facing consent UI needs the
exact serial, per §3.2 — the Planner never does), Wi-Fi SSIDs/passwords,
credentials of any kind, raw exception text, browsing/registry contents. The
Planner reasons about *classes* of hardware and *install steps*, never about
the client's actual data.

### 2.3 The outbound tripwire — defense in depth against schema bugs

An allowlist schema is only as good as the code that fills it in. A second,
independent layer sits between the Executor and any network call carrying
plan state to a Planner endpoint (local or remote): an outbound scanner
modeled directly on `apps/gramota-kyc`'s `scanForPII` — refuses to send any
request containing an image, a `data:` URI, a blob over a small size
ceiling, or a key-shaped string matching password/token/ssid/mac/serial
patterns. Like `scanForPII`, it **fails closed**: on a match, the call is
refused and the session drops to `HUMAN_STEP_REQUIRED` rather than silently
stripping the offending field and sending the rest. This is new code (no
existing crate does exactly this for install-plan state) and should inherit
`gramota-kyc`'s own discipline of explicit adversarial test vectors per leak
class before it is trusted (§6).

### 2.4 Where the Planner executes — three tiers, resolving PMO 1 §5.1

| Tier | Where the Planner runs | What leaves the device | Provability story |
|---|---|---|---|
| **A — Air-gapped** (default recommended, matches the licensing model's no-telemetry doctrine verbatim) | An on-device model. `network-fetch` is permitted only for digest-pinned OS-vendor image mirrors, never for any LLM endpoint. | Nothing Planner-related. | Trivial and absolute: the client (or their firewall log) can observe **zero** LLM-related egress for the whole session. Provable by absence, not by trusting an enclave. |
| **B — Direct-to-provider** (client's own device calls the model API directly — the same single-named-host allowlist shape `crates/yagabona`'s manifest already uses for `api.anthropic.com`) | The redacted `InstallPlanState` goes straight from the client's device to the model provider. **Postern is not in this data path at all.** | Only the schema-restricted, tripwire-checked plan state (§2.2–2.3). | Provable to whoever verifies: (i) the open-source Executor/Planner glue code, (ii) the reproducible build + `os_roothash`/`image_digest` of the environment that ran it (extends `os/ATTESTATION.md`'s chain to the portal's own image), (iii) the tripwire's own code — all inspectable *before* granting `network-fetch` for the LLM host. Postern's absence from the path is architectural, not a promise. |
| **C — Postern-managed relay** (convenience SKU; Postern holds the API key/billing) | Postern's own confidential VM, built on `os/cloud.nix`. | Same redacted plan state as Tier B, now also visible in principle to whatever runs inside that VM. | The client's Executor performs a **peer-verify handshake** against the relay before sending anything, reusing `postern-seal-companion`'s `AttestationReport`/`Expected`/`Verdict` types and its fail-closed "no anchor ⇒ `Unverified`, never `Genuine`" rule verbatim. The client pins Postern's published relay measurement as `Expected.measurement`; a mismatch is a **local, fail-closed refusal to send**, not a remote promise. |

Tier selection is bound into the `InstallGrant` (§4) — a license/session may
require Tier A ("air-gapped only" SKU for privacy-maximalist or regulated
clients) or permit B/C.

### 2.5 The honest ceiling on Tier C's provability

Tier C's mechanism is real, vector-tested code
(`crates/postern-seal-companion/src/snp.rs`) — chained to AMD's hardware
root, with CRL revocation checking, tested against a captured real Milan
report fixture. But the repo's own label for that crate applies verbatim
here: **"vector-tested ≠ attested."** Tier C's provability claim is
conditional on two things actually being true at the time of use: (1)
Postern's relay is genuinely running on real SEV-SNP hardware Postern
controls (not yet true — nothing in this repo has been attested on real
hardware Postern controls), and (2) the client's software actually performs
the peer-verify step rather than silently skipping it on failure. TDX is a
harder wall still: `postern-seal-companion`'s TDX path is **permanently,
by-design fail-closed** at its default entry point pending a real hardware
run — so Tier C can only be soundly offered on SEV-SNP infrastructure today,
never TDX, until that changes. Both facts are stated here so the portal's
marketing cannot silently outrun the crate's own honesty rails.

### 2.6 Executor placement — reusing PMO 1's three shapes, adding the attestation-before-consent gate

PMO 1 §2.4 already defines where the Executor (the privileged "hands") runs:
bare-metal live/PXE image, inside a Chiostro confidential-VM target, or
under enterprise fleet orchestration. This document adds one hard rule
across all three: **no privileged verb (§3) may run before the Executor's
own environment is verified** — either the measured-boot chain (bare-metal:
`os/attested.nix`'s erofs + dm-verity + UKI + TPM2 discipline, applied to
the portal's own image) or the Seal-gate handshake (Chiostro/CVM:
`crates/postern-seal-companion/src/{gate,snp}.rs`, reused verbatim). This
extends the Chiostro idiom "verify before you connect" to **"verify before
you consent"** — the first `InstallConsentRecord` (§3) cannot even be
constructed by a UI that hasn't first shown the client a passing
verification result. Same honesty ceiling as §2.5 applies: the mechanism is
real; nobody has yet run it against real target hardware from this repo.

---

## 3 · Least privilege + consent-gating

PMO 1 §3.6 sketches a `portal-gate` consent-spine tier with seven boolean
crossings. This section upgrades that sketch to the **signed, time-boxed,
per-target `ConsentRecord`** model already built and tested in
`apps/noporis-bridge-glue/src/consent_record.rs` — strictly stronger than a
boolean toggle, because a boolean can be flipped by anything that can write
the state file, while a signed record can only be produced by whoever holds
the operator's key.

### 3.1 `InstallConsentRecord` — the signed authorization for one privileged step

```
InstallConsentRecord {
  id, session_id,
  verb:          Verb,             // one of the fixed 8 (PMO 1 §2.3):
                                    // probe / partition / format / apply-image /
                                    // write-bootloader / driver-install /
                                    // credential-submit / network-fetch
  target:        TargetBinding,    // exact disk SERIAL + model + capacity —
                                    // never a /dev/sdX-style path, which can
                                    // reorder between boots (PMO 1 §5.5)
  scope:         Single | Session,
  issued_at, expires_at,
  operator_pub, signature          // Ed25519 (reference; a real device would
                                    // use the same PQ-hybrid pattern noted as
                                    // the honest gap in consent_record.rs)
}
```

Mints from a **local, session-only `ConsentAuthority`** the operator's own
device holds — generated fresh per session, destroyed at session end,
exactly like the near-side key in `consent_record.rs`. Postern never sees
this key. The **5-step fail-closed check**, run before every privileged
syscall, is the existing pattern verbatim: signature → session binding →
**target binding** (exact serial match, not a path — this is the direct fix
for PMO 1's open question §5.5, where a `/dev/sdX`-style consent screen is a
classic installer footgun) → verb → time-box. A record minted against disk
serial `WD-X1` cannot be replayed against disk serial `WD-X2`, cryptographically,
the same way a `ConsentRecord` minted `GooglePlay→Clean` cannot be replayed
reversed.

### 3.2 Scope rules — irreversible verbs require a live, synchronous human tap

Not every verb gets the same scope discipline:

- **Irreversible verbs** (`partition`, `format`, `apply-image`,
  `write-bootloader`) — scope **must** be `Single`, and minting the record
  **must** happen at the moment of use, from a UI showing the exact disk
  serial, model, and capacity currently probed — never from a pre-authorized
  batch the operator can't see the specifics of. This is a hard rule, not a
  default, and it holds even under a fleet `InstallPolicy` (§3.3): a
  pre-signed policy can bound the *category and target class*, but the
  live-tap requirement for the specific instance is not waivable outside the
  explicit unattended-fleet exception below.
- **Low-risk verbs** (`probe`, `driver-install`) — `Session` scope is
  acceptable; one yes covers the rest of the session.
- **`credential-submit`** — always `Single`, and never logged beyond "this
  verb ran" (§5) — the credential itself is attribution-sensitive in a way
  a disk write isn't (a digest of a low-entropy product key is itself a
  meaningful oracle, unlike a digest of an OS image).

### 3.3 `InstallPolicy` — the "signed policy pre-authorizes a bounded set" path, for fleets

For enterprise/unattended rollout (PMO 1 §2.4c), an IT admin signs an
`InstallPolicy`: a session-scoped bundle of narrowly-bounded
pre-authorizations (e.g., "format only a disk whose model+serial matches
this asset-tag manifest row; install Ubuntu 24.04 only; no `network-fetch`
beyond the pinned mirror"). Still time-boxed, still individually revocable,
still fully logged. Critically: **the Executor still independently
re-derives the target binding against the live hardware probe** before
acting — a pre-authorized policy is bounded by what it names, not by what
the admin assumed was true when they signed it, so a mismatched asset tag
still fails closed rather than silently trusting stale metadata.

### 3.4 Four revocation paths (unchanged from the existing pattern)

Reused verbatim from `ConsentLedger`: (1) explicit per-record revoke by id,
(2) close a verb lane wholesale, (3) kill-switch (`revoke_all`, fans out,
idempotent), (4) passive time-box expiry. `Single`-scope records
additionally self-retire after one use.

### 3.5 The kill-switch and the atomic-commit boundary — answering PMO 1 §5.2

NoporIS's kill-switch invariant ("drop the span, never destroy sealed wallet
state") works because the wallet is never touched by the crossing it's
guarding. A disk write is the opposite case: the entire point is to change
persistent state, irreversibly. This document's answer, concretely:

- Every privileged verb is one **journaled transaction**. Before executing,
  the Executor writes an **intent record** to the local, tamper-evident
  trail (verb, target binding, a pre-image reference such as the
  partition-table hash before the write); only after the underlying
  operation completes does it write a **commit record**.
- The kill-switch is polled **between steps**, never mid-step. If it engages
  mid-verb, the Executor finishes only the atomic primitive already in
  flight (e.g., a partition-table commit finishes; it is never left
  half-written) and halts **before starting the next step**.
- This is stated plainly, not softened: **the kill-switch halts the next
  step. It does not, and cannot, un-write bytes already committed to
  disk.** A disk wipe that is 40% through when the switch is thrown will
  have wiped that 40%. The UI must say exactly this — "halts before the
  next step; cannot undo what's already written" — rather than imply an
  instant, universal abort. Any UI copy that promises otherwise is a lie
  this document explicitly refuses to write.
- This journaling design is new [SPECULATIVE / NEW] — no existing Postern
  crate solves "safely interruptible destructive disk I/O." It needs its
  own concrete transactional spec (partition-table double-buffering,
  checksummed pre-images, resumability after a crash mid-transaction) before
  anyone builds it; this document only fixes the *invariant* (halt-before-
  next-step, never claim instant undo), not the implementation.

### 3.6 The audit trail — same idiom, extended

Every consent decision (grant **and** deny) and every intent/commit record
(§3.5) goes into the same hash-chained, append-only, `fsync`'d trail idiom
already built three times in this repo (`crates/postern-trail`,
`crates/yagabona/src/trail.rs`, `apps/noporis-bridge-glue/src/audit.rs`):
verb, target binding, decision, the consent-record id, and — for
`network-fetch`/`credential-submit` — a **digest only**, never payload
bytes and never the credential itself (matching `audit.rs`'s "attribution,
not confidentiality" stance, with the one deliberate exception that
`credential-submit` does not even get a digest — see §3.2). The trail is
local-only, client-owned, `fsync`ed before any privileged action proceeds
(fail-closed: if the trail can't be written, the action doesn't happen), and
**never auto-transmitted to Postern** — it exists for the client's own
forensics/compliance, exportable on their terms only.

---

## 4 · The license as a security boundary

`enterprise/licensing` already models a coarse, offline-verifiable
tier/seats/expiry grant (master → sub, Ed25519 chain, CRL revocation). That
is the right shape for "does this org/person have a valid license," but it
is deliberately **not** fine-grained enough to be *the* authorization for a
privileged disk operation — and it should not become one. This design keeps
licensing coarse and consent (§3) fine-grained, and adds exactly one new
token type to bridge them.

### 4.1 `InstallGrantPayload` — a new, narrowly-scoped sibling token

```ts
interface InstallGrantPayload {
  v: 1; typ: "install-grant";
  master_pub: string;   // chains to the org/personal master — same offline
                         // Ed25519 verify as every other sub token
  sub: string;           // the technician/operator label
  iat: number; exp: number;   // SHORT-lived — hours to days, not months
  jti: string;            // CRL-revocable, same mechanism as MasterPayload/SubPayload

  planner: "air-gapped" | "direct-to-provider" | "postern-relay";  // binds
                          // WHICH privacy tier (§2.4) this grant even permits

  scope: {
    images: string[];        // allowed OS+channel identifiers, or an explicit
                              // sha256 allowlist for the image-manifest check
    verbs: Verb[];             // subset of the fixed 8 verbs this grant
                                // category-permits — NOT a blanket admin bit
    max_devices?: number;
    device_pub?: string;       // optional: pin to one operator device's local key
  };
}
```

This is a `SubPayload`-shaped extension (same `v`/`master_pub`/`iat`/`exp`
fields, additive `jti` for CRL, verified with the exact same offline chain
logic `enterprise/licensing/src/{status,crl}.ts` already implements) — no
new signing infrastructure, no new trust root, just a new, more tightly
scoped payload shape signed by the same org master key.

### 4.2 Why this is a scoped authorization, not a blanket admin token

Four properties, each load-bearing:

1. **It expires quickly** (hours-to-days, not the months a corporate master
   token runs) — a leaked/forgotten grant self-limits.
2. **It is revocable** via the existing CRL mechanism
   (`enterprise/licensing/src/crl.ts`, the same `revoked_jti` /
   `revoked_master_pub` fields, the same soft-offline freshness grace) —
   revoking one grant doesn't require revoking the whole org's license.
3. **It names a bounded scope** — which images, which verb subset, which
   privacy tier, optionally which device — never "everything, forever."
4. **It is necessary but never sufficient.** Even a valid, unexpired,
   correctly-scoped `InstallGrant` does not authorize a single privileged
   syscall on its own — the Executor additionally requires a live, per-
   instance `InstallConsentRecord` (§3.1), signed by a **separate,
   locally-generated key Postern never sees**. Two independently-rooted
   keys — Postern's vendor/master chain (the ceiling: what category of
   destructive action is even in scope) and the operator's local,
   session-only `ConsentAuthority` (the trigger: yes, do *this exact*
   action, *now*) — must both hold. Postern revoking a license collapses
   the ceiling for the whole session; a human declining or revoking a
   `ConsentRecord` stops one specific action. Neither authority alone is
   enough. This mirrors, deliberately, the split already present in this
   repo between licensing (coarse: tier/seats/DUNS/expiry) and consent
   (fine-grained: capability/direction/time-box) — this design keeps that
   separation rather than collapsing it, which is exactly what would turn
   the license into the blanket admin token this section is designed to
   avoid.

### 4.3 Offline-first, same as everywhere else

`InstallGrantPayload` verifies exactly like a `SubPayload` — fully offline,
Ed25519 chain to the vendor pubkey shipped in the portal. A CRL freshness
check runs at session start and periodically during long fleet sessions
(same soft-offline grace as `max_stale_secs`), but the granular per-verb
path (§3) never needs network at all — a fully offline, no-connectivity
bare-metal install can still be completely consent-gated, as long as the
`InstallGrant` was cached before going offline. This preserves the
licensing model's non-negotiable "no telemetry, no phone-home, not for
enforcement" principle even for this product's much more privileged
capability class.

### 4.4 Personal-free doesn't mean ungated

`personal` tier needs no license token at all, per the existing doctrine —
but that waives the license **fee**, never the consent gate. A personal,
single-laptop install with zero token still requires a live
`InstallConsentRecord` for every irreversible verb, exactly as a corporate
rollout does. "Free" and "unconsented" are never the same thing in this
design.

---

## 5 · Data handling — what exists, where, and what (if anything) leaves

| Data | Lives where | Lifetime | Ever leaves the device? |
|---|---|---|---|
| Hardware inventory (disk models/serials, NIC count, TPM presence, Secure Boot state) | Executor's `probe` result; a bucketed/classed form also enters the Planner's `InstallPlanState` (§2.2) | Session only, in Executor/enclave memory | Only the coarse, bucketed `classId` form, and only under Tier B/C Planner (§2.4). Exact serials stay local — they're needed for the human-facing consent UI (§3.1), never for the Planner. |
| Partition layout / native answer-file body (`autounattend.xml`, kickstart, autoinstall YAML) | Executor memory + a digest in the local trail | Session; the answer-file body is an opaque blob the **target OS's own installer** consumes — never round-tripped through the Planner (PMO 1 §2.2) | No |
| Product key / activation credential (`credential-submit`) | Operator input → Executor → target OS's native installer, once | Session only; zero persistence | **Never** — not to Postern, not to the Planner (any tier), not even to the local trail as a digest (§3.2 — a hash of a low-entropy key is itself an oracle) |
| Wi-Fi SSID/password, if a `network-config` verb exists | Same custody model as `credential-submit` | Session only | Never leaves; never shown to the Planner |
| `ConsentAuthority` signing key | Operator's device only | Generated fresh per session, destroyed at session end | Never — Postern never holds or sees it |
| `InstallGrant` / license keys | Local device (verification only) + Postern's license service (issuance/CRL) | Grant is short-lived (§4.1); CRL checks are freshness-bound, offline-tolerant | Only the `jti`/status check against the CRL — reveals "this grant's revocation status," never any install data |
| Local audit trail | Client's own disk, hash-chained, `fsync`'d | Client-owned; persists until the client deletes it | Never auto-transmitted; exportable by the client on their own terms only |
| Redacted `InstallPlanState` (Tier B/C only) | Wire, to the model provider or Postern's attested relay | Ephemeral per call | **Yes, by design** — this is the one thing meant to leave, and it is schema-restricted (§2.2) and tripwire-checked (§2.3) before it does |

**Metadata minimization, honestly bounded:** even a schema-restricted,
tripwire-checked plan request carries request size, timing, and (absent
Tor/onion routing) source IP — the same honest limit
`crates/postern-courier`'s own module docs already state: AEAD sealing
hides payload content, never traffic shape. Routing Tier B/C Planner calls
over `crates/postern-tor` (with per-identity circuit isolation, already
built) closes the IP-correlation vector; it does not close the
size/timing one — stated here rather than left implicit.

---

## 6 · Honest limits — where the client must extend trust, plainly stated

This section exists because the repo already has a working discipline for
exactly this problem (`docs/design/bridge-trust-boundaries.md`'s honest-
qualifier rules) and this document follows it rather than reinventing a
looser standard.

- **The OS vendor's own binaries are outside this boundary.** Windows,
  RHEL packages, and their update/telemetry behavior are Microsoft's and
  Red Hat's, not Postern's, to attest. The portal attests that a
  genuine, digest-matched vendor image was written — **never** that the
  vendor's OS itself is trustworthy, private, or backdoor-free. Same wall
  PMO 1 already names (§3.5, §6); this document does not weaken it.
- **Activation/entitlement servers are entirely outside Postern's trust
  boundary.** `credential-submit` makes the agent a courier for a
  credential the operator already owns — Postern cannot grant, audit, or
  see what Microsoft's or Red Hat's own activation service does with it.
- **Client-side confidential-compute hardware (SEV-SNP/TDX) is not present
  on most machines actually being freshly provisioned today.** The
  "hardware enclave" story realistically applies to Postern's own Tier-C
  relay infrastructure and to Chiostro-shaped VM targets — **not** to a
  typical bare-metal laptop being reinstalled, which usually has no CVM
  hardware at all. On that far more common target, the Executor's own
  integrity rests on TPM2-based measured boot (widely available), and the
  Planner's privacy rests on the schema/tripwire architecture (§2.2–2.3),
  **not** on memory-confidentiality hardware. A design or a pitch that
  implies "your laptop runs the agent in a hardware enclave" would be
  false for the common case; this document deliberately does not make
  that claim.
- **"Verifiable" is not "verified."** Every provability claim in §2 depends
  on someone actually running the check — comparing a measurement,
  performing a peer-verify handshake, reading the open-source
  tripwire/glue code. A client who never runs the check is, in practice,
  trusting a promise, even though the mechanism is designed so the check
  is possible, scriptable, and third-party-auditable. This document adds
  this as an explicit fourth inequality alongside the repo's existing
  three: **`signed ≠ attested`, `built ≠ booted`, `vector-tested ≠
  attested`, and now `verifiable ≠ verified`.**
- **TDX cannot back Tier C today.** `postern-seal-companion`'s TDX path is
  permanently, by-design fail-closed at its default entry point pending a
  real hardware run — Tier C's attestation claim can only be soundly made
  on SEV-SNP infrastructure until that changes.
- **Nothing described here has been built, let alone attested on real
  hardware Postern controls.** This inherits verbatim from
  `postern-seal-companion`'s own honesty label. The portal's Executor and
  relay images would need a real reproducible-build-then-boot-then-attest
  cycle before any claim in this document moves from "designed to be
  provable" to "proven."
- **A rooted or firmware-compromised host defeats every boundary here**,
  exactly as it defeats Porog, NoporIS, and the Waydroid tier. This design
  raises the bar (verify-before-consent, measured boot of the executor
  image) but does not and cannot claim to solve Evil-Maid-class firmware
  compromise.
- **A corporate `InstallGrant`'s organizational-identity claim is only as
  strong as the DUNS binding underneath it**, which today is honor-system,
  format-only validation (`enterprise/licensing/LICENSING-MODEL.md`'s own
  documented TODO) — a fleet-scale grant claiming "issued to Acme Corp,
  DUNS verified" inherits that gap until real D&B verification is wired
  up.
- **The redaction/tripwire code (§2.2–2.3) is new and unbuilt.** No
  existing crate does exactly this for install-plan state. It should not
  be trusted more than `gramota-kyc`'s `scanForPII` is trusted today —
  which is to say, only after the same discipline of explicit,
  adversarial per-leak-class test vectors this repo already demonstrates
  is real work, not a checkbox.
- **The kill-switch halts the next step; it does not undo the last one.**
  Stated a second time here deliberately (§3.5), because it is the single
  claim in this whole document most likely to get oversimplified into
  marketing copy that isn't true.

---

## 7 · Cross-reference — PMO 1's open questions this document addresses

| PMO 1 §5 item | Where this document answers it |
|---|---|
| §5.1 Remote-LLM brain vs. no-phone-home doctrine | §2.1–§2.4 — resolved as two independent knobs (what the Planner sees vs. where it runs), three client-selectable tiers, bound into the `InstallGrant` (§4.1) |
| §5.2 Destructive actions and the kill-switch's atomic-commit boundary | §3.5 — journaled intent/commit transactions, kill-switch polled between steps only, explicit refusal to claim instant undo |
| §5.3 Attestation-gap mislabeling risk | §2.5, §2.6, §6 — the `verifiable ≠ verified` inequality, TDX/SEV-SNP honesty ceiling, explicit refusal to imply hardware-enclave protection on hardware that doesn't have it |
| §5.4 Vendor-credential (BitLocker/LUKS key, activation key) custody | §3.2, §5, §6 — `credential-submit` is always `Single`-scope, never logged even as a digest, never leaves the device, Postern is explicitly outside that trust boundary |
| §5.5 Prompt-injection / plan-tampering, and disk-identity confusion | §1 (Planner cannot execute), §3.1 (`TargetBinding` is an exact serial, cryptographically pinned, never a reorderable `/dev/sdX` path) |
| §5.9 Ephemeral executor key custody / provenance receipt trust root | §2.6 — attestation-before-consent gate; the receipt's trust bottoms out at the same measured-boot/Seal-gate chain, with the same honesty ceiling as §2.5 |

---

## 8 · Honesty ledger — real vs. speculative, at a glance

| Claim in this document | Status |
|---|---|
| The allowlist `InstallPlanState` schema + outbound tripwire | **[SPECULATIVE / NEW]** — pattern borrowed from `gramota-kyc`'s `scanForPII` (real, tested) and the consent-spine's `normalize()`-to-deny idiom (real, tested); the specific install-plan shape is new and unbuilt |
| The three Planner deployment tiers (air-gapped / direct-to-provider / Postern-relay) | **[SPECULATIVE / NEW]** as a product structure; each tier's underlying mechanism (Yagabona's single-host allowlist, `postern-seal-companion`'s peer-verify) is real |
| `InstallConsentRecord` (signed, time-boxed, target-bound, per-verb) | **Directly reuses** `apps/noporis-bridge-glue/src/consent_record.rs`'s real, tested 5-step check and 4 revocation paths — the `TargetBinding` field and the verb enum are new |
| `InstallPolicy` for fleet pre-authorization | **[SPECULATIVE / NEW]** — no existing code; the "pre-authorize a bounded set, still individually re-derived at execution time" pattern is this document's proposal |
| The kill-switch atomic-commit boundary | **[SPECULATIVE / NEW]** — the *invariant* (halt-before-next-step, no instant undo) is fixed here; the transactional implementation (journaling, resumability) is explicitly unspecified and flagged as needing its own design pass |
| `InstallGrantPayload` (license as scoped authorization) | **Extends** `enterprise/licensing`'s real, shipped `SubPayload`/CRL machinery — the payload shape and the "necessary but not sufficient, paired with a local consent key" rule are new |
| The audit trail (intent/commit + consent decisions, digest-only) | **Directly reuses** the real, tested hash-chained trail pattern (`crates/postern-trail`, `crates/yagabona/src/trail.rs`, `apps/noporis-bridge-glue/src/audit.rs`) |
| Tier C's SEV-SNP peer-verify handshake | **Real, vector-tested mechanism** (`crates/postern-seal-companion/src/{gate,snp}.rs`) reused for a new purpose; **never attested on real hardware Postern controls**, and TDX is permanently fail-closed at its default entry point |
| "Client-side confidential enclave protects the Planner on the target machine" | **Explicitly NOT claimed** as a general story (§6) — most client hardware lacks SEV-SNP/TDX; the privacy claim rests primarily on the schema/tripwire architecture, not on enclave hardware, except on Postern's own Tier-C infrastructure |
| Every threat-model entry in §1 | Grounded in real, cited primitives for the mitigation column; the adversary capabilities are this document's own analysis |

*Design and scaffold only. UNAUDITED. Do not treat any schema, token shape,
or claim in this document as a security control. `signed ≠ attested`, `built
≠ booted`, `vector-tested ≠ attested`, `verifiable ≠ verified`. Product
name(s) pending trademark clearance. Never "Postern Windows," "Postern
Ubuntu," or "Postern RedHat." BLCH is worthless and is not a security. Not
legal advice.*
