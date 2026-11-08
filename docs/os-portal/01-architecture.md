<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- Copyright (c) Postern Labs and Postern community contributors -->

# The OS Portal — a desktop OS-provisioning bridge (architecture)

**Status: DESIGN CONCEPT ONLY. Nothing in this document is built, deployed, or
audited.** This is Design PMO 1's architecture pass on a *new* product
concept: a desktop portal, gated by license and consent, that uses an AI
agent to install an operating system for a client. No code exists for this
product. Every diagram, state machine, and "reuses X" claim below is a
**design intent** grounded in real primitives that already exist elsewhere in
this repository (cited by path). Where a claim is genuinely new territory —
not covered by any existing crate, app, or spec — it is flagged
**[SPECULATIVE / NEW]**. Nothing here is a security claim. `written ≠ built`,
`built ≠ booted`, `designed ≠ audited` — the same discipline every other
product doc in this tree carries.

The deep trust/privacy threat-model pass is explicitly **out of scope here**
and handed to PMO 2; this document defines the architecture PMO 2 red-teams.

---

## 0 · Positioning — where this sits in the bridge family

Postern's existing "two-worlds bridge" products all guard a crossing between
something the user already has and something new they want to reach, and each
is named for a distinct piece of the same folklore geography:

| Product | Folklore shape | What it bridges |
|---|---|---|
| **Postern** | the fortress's own postern gate | the suite brand itself |
| **Porog** (`android-container/profile`) | the threshold — door between two worlds | stock Android ⟷ a hardened managed-profile workspace, on the *same* device |
| **NoporIS** (`android-bridge/persona`, `apps/noporis-gate`) | the guarded bridge / the Kalinov crossing | a clean persona ⟷ a Google-Play persona, both on the *same* phone |
| **Sloboda** (`apps/sloboda`) | the settlement outside the fortress walls | a Postern-controlled Linux host ⟷ a non-attestable Waydroid Android container |
| **Chiostro** (`os/cloud.nix`, `docs/specs/POSTERN-CLOUD.md`) | the cloister — a private enclosure built inside someone else's walls | a Postern OS workstation ⟷ a rented confidential-VM host |

The OS Portal is the next shape in that geography: it bridges **bare
metal or a VM the client owns ⟷ a chosen operating system installed onto
it**, using an AI agent as the hands that do the crossing. It is *not*
Postern OS Desktop's installer (that already exists, `os/desktop.nix`, and
needs no bridge — it's Postern's own image). This product's job is
installing **someone else's** OS (Windows, Ubuntu, RedHat, and others) on the
client's behalf, honestly, and provably.

### Proposed name — PROPOSED, pending trademark clearance, like every other mark in this family

**Novosel** *(Slavic "novosel" — the newcomer / new settler, the one who
moves into a freshly-built home)*. It completes the toponymy started by
Sloboda ("the settlement") and Porog ("the threshold"): Novosel is the one who
crosses the threshold into the new house the portal just raised. Alternative
considered: **Zodchiy** (the legendary master-builder figure) — rejected as a
primary candidate because its best-known telling (the builders of a famous
cathedral blinded so they could never build its equal again) is a poor brand
association for a product whose entire pitch is trustworthy, repeatable
installs; kept here only as a documented alternative. **Neither name is
committed.** Whatever ships, the same rails NoporIS/Porog/Sloboda already
carry apply verbatim:

- **NEVER "Postern Windows," "Postern Ubuntu," or "Postern RedHat."**
  Windows/Ubuntu/RedHat/"others" are used **nominatively only** — the portal
  *installs* them; it does not rebrand, fork, or claim to secure them. A
  freshly-installed Windows box is Microsoft's Windows, running under
  Microsoft's own defaults, full stop. Any hardening the portal itself
  performs must be named and scoped precisely (§3), never implied as a
  blanket "Postern-secured Windows."
- **The honest one-liner (draft, keep verbatim once adopted):** *"Novosel
  installs the OS you chose, using an agent that shows its work. It attests
  its own installer, not the OS it installs — a Postern Seal only exists
  end-to-end when the OS being installed **is** Postern OS."*
- Personal use free-forever doctrine applies to the *portal's own license
  gate* (§4.1) exactly as it does everywhere else in Postern Labs' catalog —
  see `enterprise/licensing/LICENSING-MODEL.md`. It does **not** and cannot
  waive Microsoft's Windows licensing or Red Hat's subscription terms — those
  remain the OS vendor's own business, entirely separate from Postern's
  license spine (§3.5).
- BLCH is worthless and is not a security. Not legal advice.

---

## 1 · End-to-end flow

```
 ┌────────────┐   ┌───────────────┐   ┌────────────┐   ┌───────────────┐   ┌─────────────┐   ┌──────────────┐
 │ TARGET      │──▶│ LICENSE GATE  │──▶│ PLAN        │──▶│ CONSENT REVIEW│──▶│ EXECUTE      │──▶│ ATTEST OUTCOME│
 │ SELECTION   │   │ (offline      │   │ (agent      │   │ (per-step,    │   │ (ephemeral,  │   │ (client       │
 │             │   │  verify)      │   │  drafts a   │   │  default-deny │   │  attested    │   │  verifies     │
 │             │   │               │   │  typed plan)│   │  toggles)     │   │  executor)   │   │  before use)  │
 └────────────┘   └───────────────┘   └────────────┘   └───────────────┘   └─────────────┘   └──────────────┘
```

### 1.1 State machine (design intent)

```
                         ┌─────────────────────────────────────────────────────────────┐
                         │                            IDLE                              │
                         └───────────────────────────────┬─────────────────────────────┘
                                                           │ operator picks OS + target
                                                           ▼
                                              ┌─────────────────────────┐
                                              │     TARGET_SELECTED      │  (Windows | Ubuntu | RedHat | other;
                                              │                          │   bare-metal | VM | Chiostro CVM)
                                              └────────────┬─────────────┘
                                                            ▼
                                              ┌─────────────────────────┐
                                              │      LICENSE_CHECK       │  offline verifyChain() against the
                                              │  (enterprise/licensing)  │  vendor pubkey shipped in the portal
                                              └──────┬───────────┬───────┘
                                    personal-free /   │           │ expired / revoked / invalid
                                    valid / in-eval    │           ▼
                                                       │   ┌───────────────────┐
                                                       │   │  DENIED (graceful)│──▶ back to IDLE, data untouched
                                                       │   └───────────────────┘
                                                       ▼
                                              ┌─────────────────────────┐
                                              │          PLAN            │  agent drafts a TYPED, DATA-ONLY
                                              │   (agent, network-       │  install manifest: partition scheme,
                                              │    scoped, see §2.2)     │  answer-file, driver list, per-step
                                              └────────────┬─────────────┘  capability requests
                                                            ▼
                                              ┌─────────────────────────┐
                                              │     CONSENT_REVIEW        │  each privileged verb in the plan is
                                              │  (consent-spine pattern,  │  ONE crossing lever: diskWipe,
                                              │   default DENY, §3.6)     │  partition, imageWrite,
                                              └──────┬────────────┬───────┘  bootloaderWrite, credentialSubmission,
                                     all consented    │            │ any denied  driverInstall, networkFetch
                                                       │            ▼
                                                       │   ┌───────────────────┐
                                                       │   │   PLAN_REJECTED    │──▶ agent re-plans without the
                                                       │   │  (re-plan or halt) │    denied capability, or halts
                                                       │   └───────────────────┘
                                                       ▼
                                              ┌─────────────────────────┐
                                              │        EXECUTING          │  ephemeral, attested executor runs
                                              │  (fixed verb set only,    │  ONE consented step at a time;
                                              │   §2.3)                   │  kill-switch polled between steps
                                              └───┬──────────┬─────────┬──┘  (never mid-atomic-write, §5.2)
                          human step required      │  error   │ kill-switch engaged
                                                    │          │          │
                                                    ▼          ▼          ▼
                                    ┌───────────────────┐ ┌────────┐ ┌─────────┐
                                    │ HUMAN_STEP_REQUIRED │ │ FAILED │ │ HALTED  │
                                    │ (BIOS/UEFI toggle,  │ │ (audit │ │ (audit  │
                                    │  vendor activation, │ │  trail │ │  trail  │
                                    │  exotic driver)     │ │  kept) │ │  kept)  │
                                    └──────────┬──────────┘ └────────┘ └─────────┘
                                               │ resolved
                                               ▼ (back to EXECUTING)
                                              ┌─────────────────────────┐
                                              │      INSTALL_COMPLETE     │
                                              └────────────┬─────────────┘
                                                            ▼
                                              ┌─────────────────────────┐
                                              │      ATTEST_OUTCOME       │  Postern OS target: full os_roothash /
                                              │                           │  measured-boot chain (os/ATTESTATION.md).
                                              │                           │  Windows/Ubuntu/RedHat/other: a signed
                                              │                           │  PROVENANCE RECEIPT only — see §3.5/§6.
                                              └────────────┬─────────────┘
                                                            ▼
                                              ┌─────────────────────────┐
                                              │          VERIFIED         │  client checks the receipt/attestation
                                              │                           │  BEFORE trusting the new OS
                                              └────────────┬─────────────┘
                                                            ▼
                                                          DONE
```

This state machine is new [SPECULATIVE / NEW] but every individual state
transition borrows a real, existing pattern:

- `LICENSE_CHECK` → `enterprise/licensing/src/{status,eval}.ts`,
  `functions/license/status.js` (offline Ed25519 chain verify, graceful
  expiry, never destructive).
- `CONSENT_REVIEW` → the consent-spine (`apps/consent-contract/consent-spine.mjs`,
  `apps/noporis-gate/gate-store.mjs`): default-deny, per-capability,
  individually revocable, fail-closed on any malformed state.
- `HALTED` (kill-switch) → NoporIS's kill-switch invariant
  (`apps/noporis-gate/README.md` — "drops the span but NEVER destroys sealed
  wallet state"), adapted here to "halts the *next* step but never corrupts
  an in-flight atomic write" (§5.2 — this adaptation is itself flagged as a
  new, harder problem than the wallet case).
- `ATTEST_OUTCOME` → `os/ATTESTATION.md`'s chain, reused verbatim for a
  Postern OS target and *deliberately weakened and relabeled* for a
  third-party OS target (§3.5, §6).

---

## 2 · The AI-agent execution model

### 2.1 The core design decision: split "brain" (planner) from "hands" (executor)

The single most important architectural choice is that **the agent that
reasons about the install and the process that touches the disk are two
different trust domains**, never one. This directly extends a principle
already stated as load-bearing in this codebase's one actual "agent" crate,
`crates/yagabona`:

> "**Task execution is a safe stub.** `scheduler::Task` is a Rust trait, not
> an exec of arbitrary commands. This crate never spawns a shell or runs
> untrusted code." — `crates/yagabona/README.md`

Yagabona's `threshold::validate` produces a `Grant` or `Refusal` from a
strictly-typed **Izbushka manifest** (TOML) *before* anything executes, and
the manifest's `network` field is fail-closed to exactly `"none"` or
`"api.anthropic.com"` — there is no wildcard. That single detail is the
strongest existing evidence in the repo that an AI-agent execution model
using a scoped LLM API call is already an anticipated shape, not a
greenfield invention. The OS Portal's agent architecture generalizes this
pattern from "read/write files in a workspace" to "partition/format/image a
disk" — a materially more dangerous capability class, which is why the
brain/hands split is non-negotiable here even though Yagabona's current scope
never needed it (Yagabona's own tasks are non-destructive file operations).

```
┌─────────────────────────────┐        typed, signed PLAN         ┌──────────────────────────────┐
│  PLANNER  ("brain")          │ ─────────────────────────────────▶│  EXECUTOR  ("hands")          │
│                               │   (data, never code; §2.2)         │                                │
│ • may call an LLM API          │                                    │ • fixed, small verb set only  │
│   (scoped network allowlist,  │◀───────────────────────────────── │   (§2.3) — cannot interpret    │
│   Yagabona-style)              │   step results / consent record   │   the plan's prose, only its    │
│ • reads target-hardware facts  │                                    │   typed fields                 │
│ • drafts partition scheme,     │                                    │ • runs ON or ADJACENT TO the    │
│   answer-file, driver list     │                                    │   target (§2.4) — no other      │
│ • NEVER touches a raw block    │                                    │   option for bare metal         │
│   device                       │                                    │ • ephemeral: destroys its keys  │
│                                 │                                    │   at session end                │
└─────────────────────────────┘                                    └──────────────────────────────┘
```

### 2.2 The plan is data, never code [design principle, extends Yagabona's stance]

The planner never hands the executor a shell script, a PowerShell script, or
anything the executor *interprets as instructions to run arbitrary commands*.
It hands a **typed manifest** — a structured document whose fields the
executor's fixed code switches on (partition table entries, an answer-file
body treated as an opaque blob for the *target OS's own* installer to
consume, a driver-package list, a bootloader target). This is the same shape
Yagabona already enforces for its own (much smaller) capability set, and the
same shape the consent-spine schemas (`apps/noporis-gate/gate-state.schema.json`,
`apps/consent-contract/consent-spine.schema.json`) already use: **JSON
Schema-validated state, never eval'd code.** A malformed or hostile plan must
`normalize()` to "nothing is authorized" exactly like a malformed consent
file does today — this is the single reusable idiom that appears in every
consent-gate in the repo and should not be reinvented for the portal.

### 2.3 The executor's capability surface — least privilege, fixed verb set

[SPECULATIVE / NEW — no existing crate implements this; the design *pattern*
is reused, the verb set is new.] Proposed fixed verbs, each independently
consent-gated (§3.6):

| Verb | What it does | Danger class |
|---|---|---|
| `probe` | read-only hardware/firmware inventory (disks, NICs, TPM presence, Secure Boot state) | none — always allowed, informs the plan |
| `partition` | write a partition table to ONE named, serial-bound disk | destructive, irreversible |
| `format` | create a filesystem on ONE named partition | destructive, irreversible |
| `apply-image` / `run-installer` | feed the target OS's own native unattended-install mechanism (answer file, kickstart, autoinstall — §3) the drafted manifest | destructive (writes the OS) |
| `write-bootloader` | install/configure the bootloader for the just-written OS | destructive if targeting the wrong disk |
| `driver-install` | apply a vendor driver package the plan named | low-to-medium (can brick a device but is usually recoverable) |
| `credential-submit` | pass an activation key / subscription credential the OPERATOR supplied directly to the target OS's own installer, once, in-session | high sensitivity, zero custody (§3.5) |
| `network-fetch` | fetch ONE allowlisted artifact (an OS vendor's own ISO/mirror, or the planner's LLM API endpoint) | scoped, logged |

No verb is "run arbitrary shell." This mirrors Yagabona's stub-execution
stance and is stricter than it needs to be for file operations precisely
*because* these verbs touch raw block devices — the blast radius of a
compromised or confused agent here is "the client's data is gone," not "a
scoped workspace file was misplaced."

### 2.4 Where the executor runs — three deployment shapes, stated honestly

There is no single answer to "where does the agent run"; it depends on what
kind of target is being provisioned. The honest architecture has three
shapes, not one:

**(a) Bare-metal target (the client's own physical machine).** The executor
**must** run on that same physical machine — there is no remote way to
partition a disk you are not attached to. It is a minimal, ephemeral,
network-boot or USB-boot live environment, built with the *same reproducible/
measured-image discipline* as `os/attested.nix` (erofs + dm-verity + UKI),
so its own integrity is checkable by the client **before** the client grants
it the first privileged consent — extending the Chiostro Seal-gate idiom
("verify before you connect", `docs/specs/POSTERN-CLOUD.md` §4) to "verify
before you consent." The *planner* (brain) may run remotely from this same
environment over the scoped network allowlist, or — if the operator declines
`networkFetch` for the LLM host — the plan must be pre-approved offline and
carried in, with no live agent reasoning during execution. This tension
(remote LLM brain vs. Postern's no-phone-home doctrine) is flagged as an
open question in §5.1, not resolved here.

**(b) VM / Chiostro confidential-VM target.** When the target itself is a
new confidential VM (e.g., standing up Postern OS Desktop, or even a
Windows/Ubuntu guest, as a Chiostro cloud workstation per
`docs/specs/POSTERN-CLOUD.md`), the executor runs **inside the target guest**
during its own first boot, and the Seal-gate handshake already implemented
in `crates/postern-seal-companion` (`src/gate.rs`, `src/snp.rs`) is reused
verbatim: the client does not trust the finished install until it has
verified `report_data = SHA-256(nonce ‖ guest_pubkey)` chains to a genuine
SEV-SNP/TDX launch measurement. This is the shape closest to something
already built in this repo.

**(c) Enterprise fleet target.** Many machines, one corporate license. The
**control-plane orchestrator** (`enterprise/cloud/control-plane/src/orchestrator.mjs`)
pattern generalizes directly: one tenant, per-tenant isolated node/session
records (`isolation.mjs`'s firmament pattern), `provision()`/`deprovision()`
semantics, and the license-binding invariant "revoke ⇒ deprovision"
(`enterprise/cloud/control-plane/src/license-binding.mjs`) applied to install
*sessions* instead of standing VMs: if the corporate master token is revoked
mid-rollout, every **not-yet-consented** planning session for that tenant is
torn down immediately; an **already-consented, in-flight local disk write**
on a bare-metal machine is a different case (§5.7) — there is no remote kill
for that, by the same no-phone-home doctrine that makes Postern's licensing
100% offline in the first place.

### 2.5 Sandboxing, ephemerality, attestability — summarized

- **Ephemeral**: the executor holds no state before the session and destroys
  its signing key at session end (mirrors NoporIS's `destroy-this-world-only`
  / `wipeProfileOnly()`, `android-common`'s shared DPC seam).
- **Least-privilege**: fixed verb set (§2.3), no shell, no interpreter of the
  plan's prose — same posture Yagabona already states for its own, smaller
  capability class.
- **Attestable**: built via the same reproducible-image pipeline as
  `os/attested.nix` / `os/cloud.nix`, so `image_digest` and `os_roothash` are
  checkable before the first consent, exactly like Postern Cloud's Seal-gate
  (§2.4a/b).
- **Sandboxed**: on bare metal, the executor *is* the entire live OS — there
  is nothing to nest it inside while it is repartitioning the disk that would
  otherwise host it, so its sandbox is "minimal OS, no persistent state,
  firewalled to the network allowlist" (same posture as `os/cloud.nix`'s "no
  cloud agents, no provider guest-tools in the image"). On a Chiostro target,
  the sandbox is the CVM hardware boundary itself.

---

## 3 · Per-OS install mechanics — honest feasibility

The mechanism is the same three-stage shape for every OS the portal
supports: **(1)** the planner drafts a native, OS-specific unattended-install
answer file from the consented plan; **(2)** the executor hands that answer
file to the target OS's *own* native installer (never a Postern
reimplementation of an OS installer); **(3)** the executor watches for
completion/failure markers, the same "grade the log against known markers"
discipline already used by `os/boot-harness/check-boot-log.sh` for Postern OS
Mobile's own boot proof. What varies per OS is how mature and complete that
native mechanism is, and where it hits a wall only a human or the OS
vendor can cross.

### 3.1 Windows — feasible, with real limits

**Genuinely automatable:** unattended install via an answer file
(`autounattend.xml`/`unattend.xml`) fed to Windows Setup, or WinPE-based
imaging (`DISM /Apply-Image` against a WIM/ESD), partitioning via the answer
file's `<DiskConfiguration>`, driver injection (`DISM /Add-Driver`), OOBE
bypass, local-account bootstrap, product-key entry in the answer file.

**Hard / not fully automatable:**
- **Activation** is Microsoft's own entitlement system (KMS/MAK/retail key
  against Microsoft's servers) — the agent can *enter* a key the operator
  supplies (`credential-submit`, §2.3) but cannot itself license Windows.
  This is categorically outside Postern's license spine (§3.5).
- **BitLocker key custody** — enabling disk encryption via the answer file is
  automatable; *who holds the recovery key* is a policy decision, not a
  technical one, and per Postern's personal-sovereignty doctrine the client
  must hold it, never Postern (open question, §5.4).
- **Driver coverage for exotic/very new hardware** — genuinely not always
  scriptable; some devices need vendor tools with their own GUIs or license
  click-throughs. Honest fallback: `HUMAN_STEP_REQUIRED`.
- **Secure Boot / UEFI firmware settings** are usually pre-req steps outside
  the OS installer's reach entirely (§3.4).

### 3.2 Ubuntu — feasible, cleanest case

**Genuinely automatable:** modern `subiquity`-based installs use
**autoinstall** (cloud-init-style YAML) — partitioning, user creation,
package selection, network config, and `late-commands` for
post-install scripting are all first-class and well-documented. (The older
debian-installer **preseed** mechanism still exists for legacy/server
netinstall paths and is likewise scriptable.) No activation step — this is
the simplest feasibility case of the four because there is no vendor
entitlement gate to cross.

**Hard parts:** proprietary GPU drivers (NVIDIA) and some Wi-Fi/firmware
blobs may need a network fetch mid-install and occasionally a reboot the
autoinstall flow has to sequence correctly; full-disk-encryption (LUKS) key
custody has the identical open question as Windows' BitLocker case (§5.4).

### 3.3 RedHat (RHEL) — feasible, one real vendor wall

**Genuinely automatable:** **kickstart** (`.ks`) is RHEL's canonical,
decades-mature unattended-install mechanism — partitioning, package sets,
`%pre`/`%post` scripting sections, all scriptable and well-documented; this
is arguably the single most mature answer-file mechanism of the four.

**Hard parts:**
- **Subscription registration** — `subscription-manager register
  --activationkey=...` is itself scriptable *if the operator supplies a
  valid Red Hat activation key/org ID*, but Postern cannot grant RHEL
  entitlements — same categorical wall as Windows activation (§3.5).
  Without registration the install completes but the system has no update
  channel — the plan must disclose this rather than silently ship an
  unregistered RHEL box.
- LUKS key custody — same open question as §3.2/§5.4.

### 3.4 "Others" (Debian, Fedora, openSUSE, Arch, …) — real work, not free

Each additional OS has its own native answer-file mechanism (Debian:
preseed/autoinstall variants; Fedora: kickstart, same lineage as RHEL;
openSUSE: **AutoYaST**; Arch: no first-class unattended installer at all —
would need a bespoke scripted `archinstall`/pacstrap flow). The three-stage
shape (§3, opening paragraph) generalizes cleanly, but **each OS is its own
integration project** — driver/firmware quirks, partition-scheme dialects,
and post-install verification markers all differ. "Others" should be
scoped and prioritized OS-by-OS, not marketed as a blanket capability.

### 3.5 The one wall that is the same for every OS: vendor entitlement is not Postern's to grant

Windows activation and RHEL subscriptions are the two clearest instances of
a general rule: **Postern's license spine (§4.1) gates the portal's own
service — it never substitutes for, bypasses, or grants the target OS
vendor's own licensing.** The agent may *carry* a credential the operator
supplies (`credential-submit`), but:
- it is never stored beyond the single install session,
- it is never transmitted anywhere Postern controls (consistent with
  `LICENSING-MODEL.md`'s "no telemetry, no phone-home, no per-user account"
  principle, extended here to third-party credentials too),
- and the portal's own attestation of the outcome (§1.1 `ATTEST_OUTCOME`,
  §6) never claims to certify that vendor entitlement — only that the steps
  the agent ran, ran, and the disk ended up in the state the plan described.

### 3.6 Consent-gating each privileged step — reusing the crossing model

Every verb in §2.3 is modeled as one crossing in a **new, fourth consent-gate
tier**, following the identical spine `apps/consent-contract/CONTRACT.md`
already formalizes for Sloboda/NoporIS/Porog:

```jsonc
{
  "schema":  "postern.portal-gate.state",
  "version": 1,
  "tier":    "install-execution",     // pinned; NEVER implies measured-boot
                                        // of the OS being installed (§6)
  "consent":    { "accepted": false, "scope": "session" },
  "killSwitch": { "engaged": false },
  "crossings": {
    "diskWipe":          { "open": false, "scope": "session" },
    "partition":         { "open": false, "scope": "session" },
    "imageWrite":        { "open": false, "scope": "session" },
    "bootloaderWrite":   { "open": false, "scope": "session" },
    "driverInstall":     { "open": false, "scope": "session" },
    "credentialSubmit":  { "open": false, "scope": "session" },
    "networkFetch":      { "open": false, "scope": "session" }
  }
}
```

Same rails as every existing tier: default DENY, `normalize()` collapses any
malformed/foreign/unknown-version file to full-deny, each crossing is a
single explicit lever the operator throws and can individually revoke, and a
kill-switch exists — adapted here to halt the *next* queued step rather than
(impossibly) un-write an in-progress disk write (§5.2). This tier is
**[SPECULATIVE / NEW]** — no code exists for it — but its *shape* is the
single most directly reusable primitive in this whole design.

---

## 4 · How this reuses Postern primitives — summary map

| Portal need | Reused primitive | Path | Status |
|---|---|---|---|
| License-gate the portal itself | Master→sub offline Ed25519 token chain, 3-tier model (personal/business-freemium/corporate-master) | `enterprise/licensing/`, `functions/license/` | **Real, shipped design** — reused unmodified |
| Revoke a corporate rollout mid-flight | CRL (freshness-bound, soft-offline), "revoke ⇒ deprovision" | `enterprise/licensing/src/types.ts` (`CrlPayload`), `enterprise/cloud/control-plane/src/license-binding.mjs` | **Real** — pattern reused, portal-specific wiring is new |
| Per-privileged-step consent | Default-deny, per-capability, revocable crossings + kill-switch | `apps/consent-contract/`, `apps/noporis-gate/` | **Real schema/kernel** — new `portal-gate` tier is new (§3.6) |
| Attest the executor before trusting it with disk access | Seal-gate "verify before you connect" handshake (nonce, channel-bound report_data) | `crates/postern-seal-companion/src/{gate,snp}.rs`, `docs/specs/POSTERN-CLOUD.md` §4 | **Real, vector-tested** — reused for a new use (pre-consent, not pre-connect) |
| Attest the install *result* | `os/ATTESTATION.md` chain (image_digest, os_roothash, measurement) | `os/attested.nix`, `os/ATTESTATION.md` | **Real, but only applies end-to-end when the target OS is Postern OS itself** (§6) |
| Scoped, capability-gated agent execution model | Izbushka manifest + `threshold::validate` fail-closed grant/refusal + hash-chained audit trail + "never spawns a shell" stance + scoped network allowlist | `crates/yagabona/` | **Real for a smaller capability class (files)** — extended here to disk-level verbs; the extension is new |
| Tamper-evident audit of every grant/denial | SHAKE-256 hash-chained, append-only, `fsync`ed trail; `verify_chain` | `crates/yagabona/src/trail.rs`, `crates/ezekiel1/src/trail.rs` | **Real** — direct reuse |
| Multi-technician / fleet RBAC over who may consent which step | Wheels-within-wheels (no layer widens itself), Chinese walls, per-tenant firmament isolation | `crates/ezekiel1/` | **Real for Consiglio's access model** — applying it to install-consent is new, proposed Wave-2 |
| Cloud/CVM target orchestration | Per-tenant isolated `provision()`/`deprovision()`, injected operator driver seam, honest `simulated:true` when no real driver is wired | `enterprise/cloud/control-plane/src/orchestrator.mjs` | **Real** — reused directly for shape (c), §2.4 |
| "Boot proof" discipline for the executor image | Marker-ladder grading of a serial console log against a shared success/failure contract | `os/boot-harness/check-boot-log.sh`, `success-markers.txt` | **Real pattern** — a new marker set for "install completed" is new |
| Postern Seal (product identity) | Reproducible build → immutable image → measured boot → attested | `os/attested.nix`, `os/ATTESTATION.md` | **Real, unmodified** — applies to the executor image and to a Postern-OS *target*; does not and cannot extend to Windows/RHEL/Ubuntu as installed (§6) |

---

## 5 · Open questions and risks — for the advisors / red-team (PMO 2)

1. **Remote-LLM brain vs. no-phone-home doctrine.** `LICENSING-MODEL.md`
   principle 2 is "no telemetry, no phone-home... not for enforcement, not
   for analytics." Yagabona's own manifest schema already carves out one
   exception (`network = "api.anthropic.com"`). Does the planner's outbound
   LLM call need the same disclosed, scoped exception here — and is a single
   named host an acceptable carve-out, or does this product require an
   on-device model to hold the doctrine? This is a real product decision,
   not an implementation detail.
2. **Destructive actions cannot be "revoked" the way a wallet crossing can.**
   NoporIS's kill-switch invariant ("never destroys sealed wallet state")
   works because the wallet is never touched by the crossing at all. A disk
   partition/format/image-write is the opposite: the whole point is to
   change persistent state, irreversibly. What is the actual atomic-commit
   boundary — does the executor journal each step so a kill mid-batch leaves
   a *recoverable*, not merely a *stopped*, disk? This needs a concrete
   transactional design before anyone builds it.
3. **Attestation-gap mislabeling risk.** The portal can attest its own
   installer and produce a provenance receipt, never the security posture of
   the OS it just installed. If marketing or UI ever implies "Postern-secured
   Windows," that repeats exactly the mistake NoporIS's README works hard to
   avoid on the Google-Play side ("separation + convenience, not privacy").
   The labeling discipline needs to be as strict here as it is there.
4. **Vendor-credential handling is a new trust surface.** No existing bridge
   product asks the user to hand it a third party's (Microsoft's/Red Hat's)
   activation credential, even transiently. `credential-submit` (§2.3) is
   the first place in the whole Postern catalog where the agent voluntarily
   touches another vendor's auth material. Needs its own explicit non-custody
   statement and probably its own audit-trail entry class.
5. **Prompt-injection / plan-tampering surface.** If the planner's context
   includes fetched content (driver catalogs, OS vendor metadata, or LLM
   output), a compromised or malicious input could steer the plan toward
   wiping the wrong disk. The fixed-verb executor + per-step consent (§2.3,
   §3.6) is the primary mitigation, but: is per-step consent granular enough?
   Does the `diskWipe`/`partition` consent screen show the *exact physical
   disk, by hardware serial*, not a `/dev/sdX`-style path that can reorder
   between boots — a classic installer footgun that has bitten real products?
6. **Fleet-scale remote kill vs. offline license doctrine.** Corporate
   customers running an incident-response scenario will reasonably want to
   halt an in-progress fleet rollout remotely. Postern's licensing is
   deliberately 100% offline. §2.4(c) proposes a freshness-bound CRL check
   between steps as the middle ground (same soft-offline pattern as
   `CrlPayload.max_stale_secs`) but this has not been validated against real
   incident-response requirements or against the doctrine that an
   already-consented, in-flight local write on a bare-metal machine has *no*
   remote kill by design.
7. **BIOS/UEFI/firmware prerequisites are often not scriptable at all**
   (Secure Boot toggle, boot order, RAID mode on some server boards). The
   product's core promise — "an AI agent installs your OS" — needs an honest,
   well-designed `HUMAN_STEP_REQUIRED` UX rather than quietly failing or
   overpromising full automation.
8. **Driver/hardware coverage is uneven and needs a real feasibility
   matrix**, especially for "others" (§3.4) and older/exotic peripherals —
   a blanket automatability claim would not survive contact with real
   hardware diversity.
9. **Ephemeral executor key custody — what roots the provenance receipt's
   trust?** The executor generates its signing key the same session it uses
   it (§2.5). The receipt is only as trustworthy as "the executor's own
   boot image was attested" (§2.4a). Does that chain need a client-side
   witnessing/nonce step analogous to the Seal-gate's freshness binding
   (`docs/specs/POSTERN-CLOUD.md` §4.1), or is boot-time attestation of the
   image alone sufficient? Needs PMO 2's judgment.
10. **License-tier fit for this product is undecided.** Is a personal,
    single-laptop Ubuntu install free-forever (matching the rest of
    Postern's personal doctrine), while only fleet/corporate provisioning is
    paid? Or does the *agent's* operating cost (an LLM API call per install)
    argue for a different tier boundary than the file-hygiene/vault-style
    apps that have zero marginal cost per personal use? This changes the
    license-gate design in §1.1/§3.5/§4 nontrivially and should be decided
    before implementation, not discovered during it.

---

## 6 · Honesty ledger — real vs. speculative, at a glance

| Claim in this document | Status |
|---|---|
| The bridge-family naming pattern (Postern/Porog/NoporIS/Sloboda/Chiostro) | **Real** — read directly from the existing repo |
| "Novosel" / "Zodchiy" as the product name | **Proposed only**, not committed, no trademark clearance sought |
| The license spine (offline master→sub, CRL, graceful expiry) | **Real, shipped design** — reused, not reinvented |
| The consent-spine kernel (default-deny, per-capability, kill-switch) | **Real, shipped design** — reused; the specific `portal-gate` tier and its seven crossings are new |
| The Seal-gate attestation-before-connect handshake | **Real, vector-tested crate** (`postern-seal-companion`) — reused for a new purpose (pre-consent, not pre-tunnel) |
| The `os_roothash`/measured-boot attestation chain | **Real** for a Postern OS target; **does not and cannot extend** to a third-party OS target beyond a provenance receipt — this document is explicit about that gap everywhere it matters |
| Yagabona's "plan is data, never code" / scoped-network-allowlist stance | **Real, shipped design**, for a materially smaller capability class (files, not disks) — the disk-level extension in §2.2–§2.3 is new and untested even as a design |
| The brain/hands split, the fixed executor verb set, the three deployment shapes | **[SPECULATIVE / NEW]** — no existing code; this is this document's actual architectural proposal |
| Windows/Ubuntu/RedHat feasibility claims (§3.1–3.4) | Grounded in the OS vendors' own public, well-documented unattended-install mechanisms (answer files / kickstart / autoinstall) — **not** grounded in anything in this repo, since no prior Postern product touches these OSes at all |
| The control-plane orchestration reuse for fleet targets | **Real, shipped design** (`orchestrator.mjs`) — its `driver` seam is explicitly "no real infrastructure spun up here" even in its own code; portal-specific wiring is new |
| Every risk in §5 | Genuinely open — none has a chosen answer in this document |

*Design and scaffold only. UNAUDITED. Do not treat any state machine, schema,
or claim in this document as a security control. Product name(s) pending
trademark clearance. Never "Postern Windows," "Postern Ubuntu," or "Postern
RedHat." Windows/Ubuntu/RedHat are used nominatively. Personal use of the
portal follows Postern's free-forever doctrine for the portal's own license
gate only — it neither grants nor waives any target OS vendor's own
licensing. BLCH is worthless and is not a security. Not legal advice.*
