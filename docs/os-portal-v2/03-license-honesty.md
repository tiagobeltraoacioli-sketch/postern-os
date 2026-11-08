<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- Copyright (c) Postern Labs and Postern community contributors -->

# The OS Portal v2 (Terem) — license honesty & the honest caveats bar

**Status: DESIGN CONCEPT ONLY. Nothing in this document is built, deployed, or
audited.** Lead architect's pass, grounded in `01-architecture.md`
(guest-runtime + Wine/Proton), `02-security-consent-privacy.md` (the
sandbox trust boundary), and the retired v1 doc's already-correct license
analysis (`docs/os-portal/01-architecture.md` §3.5, §4). This document does
not re-derive OS-vendor feasibility — it states, plainly, whose license this
is, who is liable for what, and the honest limits a client must accept
before using Terem. Same discipline as every doc in this tree:
`written ≠ built`, `built ≠ booted`, `designed ≠ audited`.

> **Merge note.** Architect 1's full pass (`A-virtualization.md`) contributes
> two corrections folded in below: **(1)** §4.4's Wine/Proton compatibility
> caveat now adopts WineHQ AppDB's own five-tier scale verbatim, rather than
> a vaguer "varies" statement, since that scale already exists and is the
> honest, non-fabricated framework to point to. **(2)** whether Valve's own
> Proton build can be redistributed outside Steam's own channel at all is an
> **open legal question**, distinct from — and prior to — the compatibility
> question; §4.4 now states it explicitly rather than assuming "Wine/Proton"
> is one settled, shippable stack.

> **Update (2026-07-16) — "nothing built" is now imprecise; here is the exact
> state.** The first Terem code exists in-tree and is committed:
> `desktop/src-tauri/src/terem.rs` (the Tauri backend / QMP spawn path) and the
> `apps/terem-gate` crate (the consent spine) **compile and pass their unit
> tests (terem-gate 32/32 + terem.rs 16) — but only under QEMU/TCG on the macOS
> workstation, never under Linux/KVM and never on hardware.**
> `os/terem-compat.nix` (the OS module that
> keeps the default attested build zero-GPL) exists and is committed but is a
> Nix module not evaluated on this non-Nix host. The license *decisions* below
> are unchanged, still design/decision-only, and still need real counsel;
> everything else this document designs remains **unbuilt, unbooted, and
> unaudited** — `written ≠ built`, `built ≠ booted`, `TCG ≠ KVM ≠ hardware`.

---

## 1 · The user-brings-own-license model

### 1.1 The rule, stated once, applying everywhere in this document

**Postern never provides, bundles, pirates, or resells a Windows, RHEL, or
any other third-party OS license.** The operator (a) already owns a license
(a retail/OEM Windows key, a Red Hat subscription, a Ubuntu install — which
needs no license at all, being free software), or (b) acquires one directly
from that vendor, exactly as they would for a real machine. Terem's role in
that transaction is **zero** — it does not broker, store, validate, or
transmit the license to anyone. The operator types their own key into the
guest OS's own installer/activation UI (Guest Mode, `01` §2.3) or simply
doesn't need one at all (Ubuntu, most Linux — App Mode's Wine layer, which
needs no OS license whatsoever since it isn't an OS, `01` §3.4).

This is **stronger** than v1's already-correct position (v1 §3.5:
"Postern's license spine gates the portal's own service — it never
substitutes for, bypasses, or grants the target OS vendor's own
licensing"), not weaker: v1 still needed a dedicated `credential-submit`
executor verb and its own non-custody statement, because an AI agent was
the thing physically entering the key into a bare-metal install. In v2,
there is no agent in the loop by default (`01` §6) — the operator interacts
with the guest's own installer directly, the same way they would on real
hardware. Postern's distance from the vendor-license transaction **did not
shrink in the pivot; it grew**.

### 1.2 Activation happens inside the guest, full stop

- **Windows**: the operator enters their product key into Windows Setup or
  `slmgr`/Settings → Activation, exactly as on physical hardware. Windows'
  own activation service (KMS/MAK/retail) talks to Microsoft's servers over
  the guest's NAT'd network (`02` §5) — Postern is not on that path, cannot
  see the key, and does not attest that activation succeeded or that the
  key is genuine.
- **RHEL**: the operator runs `subscription-manager register
  --activationkey=... --org=...` (or the interactive equivalent) inside the
  guest, against their own Red Hat account. Without registration the
  install completes but has no update channel — this is disclosed, never
  silently shipped as if registered (carried forward verbatim from v1
  §3.3).
- **Ubuntu / other free Linux**: no activation step exists. This remains
  the cleanest case, per v1 §3.2's original analysis, unchanged by the
  pivot.

### 1.3 Trademark — nominative use only, carried forward verbatim from v1

**NEVER "Postern Windows," "Postern Ubuntu," or "Postern RedHat."**
Windows/Ubuntu/RHEL/"others" are used **nominatively only** — Terem *runs*
them inside a sandbox or *translates* one app's API calls; it does not
rebrand, fork, or claim to secure them. A freshly-installed Windows guest is
Microsoft's Windows, running under Microsoft's own defaults, inside a
Postern-built sandbox — full stop. Any hardening Terem itself performs
(the sandbox boundary, the consent-gated bridges) must be named and scoped
precisely (`02`), never implied as a blanket "Postern-secured Windows." This
rule is unchanged from v1 §0 and applies to every surface: UI copy,
marketing, this document family, and code comments.

---

## 2 · Whose liability is whose

| Question | Answer |
|---|---|
| Who is responsible for the guest OS being genuinely licensed? | **The operator.** Terem neither checks nor enforces this — it has no code path to. |
| Who is responsible for the guest OS's own security/privacy/telemetry behavior? | **The OS vendor.** Same wall v1 §6 already drew for its bare-metal target; the pivot to a sandbox does not change who owns the OS's own conduct — it only changes what happens to the *host* if that conduct turns hostile (`02` §1). |
| Who is responsible if Windows activation fails, or RHEL subscription registration is misconfigured? | **The operator, working directly with the vendor.** Terem is not a support channel for Microsoft's or Red Hat's own entitlement systems, and holds no data that would let it help troubleshoot that even if it wanted to (§1.2 — Postern never sees the key). |
| Who is responsible for data loss inside a guest (the operator deletes their own guest, or a guest crashes)? | **The operator**, same as any local file they manage — `02` §4's kill-switch/destroy semantics are stated plainly precisely so this responsibility is never ambiguous. |
| Who is responsible for the app's own license/activation in App Mode? | **The operator and the app vendor** — Wine/Proton runs the app's own installer; Terem never ships, cracks, or bypasses the app's own licensing (§4.4). |

---

## 3 · Terem's own license gate — reusing the license spine unmodified

Terem, as a Postern product, is gated by the **same** offline, no-telemetry
license spine every other Postern product uses
(`enterprise/licensing/LICENSING-MODEL.md`, `functions/license/`) — this
gate is entirely about **using the Terem software itself**, never about the
guest OS's own licensing (§1), which is a categorically separate question.

| Tier | Who | Token? | What it covers |
|---|---|---|---|
| **Personal** | Individuals running Terem for personal use | **None** | Free forever, no clock, no nag — identical to every other Postern personal-tier product |
| **Business freemium** | Small business, up to 3 desktops | Vendor-signed master, 24-month window | Same shape as `enterprise/licensing`'s existing `business-freemium` tier |
| **Corporate master** | A DUNS-verified company, unlimited seats | Vendor-signed master, 6-month window (pricing TBD, disclosed as such) | Same shape as the existing `corporate-master` tier |

No new token type is strictly required — Terem can reuse
`MasterPayload`/`SubPayload` (`enterprise/licensing/src/types.ts`) verbatim,
the way v1 §4.1 proposed a new `InstallGrantPayload` only because its
disk-level executor verbs needed a scoped authorization narrower than a
license. Terem's lifecycle verbs (`01` §2.6 — create/start/stop/snapshot/
destroy a guest, or install/launch/destroy a Wine app) are not
individually as high-stakes as v1's `partition`/`format`/`write-bootloader`
were, so gating "can this operator use Terem at all" at the ordinary
license-tier grain, and gating "can this specific bridge crossing open"
at the `02`/`terem-gate` consent grain (finer, per-crossing, never the
license's job — same separation-of-concerns principle v1 §4.2 already
established and this document keeps), is sufficient. `[OPEN — same
question v1 §5.10 left open]`: is a single-guest personal install free
under the personal tier regardless of guest count, or does Terem's own
resource cost (disk space, a guest that can itself be resold/reused as a
"free Windows machine" in a way a file-hygiene app's zero-marginal-cost
tools never could) argue for a tier boundary tied to guest *count* rather
than the product itself? Not resolved here — flagged for the license/
business-model owner, not a security or architecture question.

### 3.1 Personal-free doesn't mean ungated

Per the existing doctrine (`LICENSING-MODEL.md` principle 1,
`enterprise/licensing`'s personal tier): free waives the license **fee**,
never the consent gate. A personal, zero-token Terem guest still requires
the same `terem-gate` consent for every bridge crossing (`02` §3) as a
corporate deployment. "Free" and "unconsented" are never the same thing,
carried forward verbatim from v1 §4.4.

---

## 4 · The honest caveats bar

This section exists because the product's core promise — "run another OS,
or one Windows app, right here" — needs an honest ceiling stated as loudly
as the promise itself, the same discipline Sloboda's README applies to
Play Integrity ("by design, not a bug we can fix — disclosed, never
spoofed").

### 4.1 VM overhead / performance

A Guest Mode VM is not free. Expect:

- **CPU/memory overhead**: the guest's own kernel, drivers, and background
  services compete for the same physical CPU/RAM the host uses — a guest
  is never as fast as the same OS on bare metal, and running a demanding
  guest workload alongside active host work (browsing, the node,
  wallet operations) competes for the same resources.
- **Disk I/O overhead**: a qcow2-backed virtual disk adds a translation
  layer between the guest's filesystem operations and the host's real
  disk — meaningfully slower than bare-metal disk I/O, most noticeable
  on install/update-heavy workloads (a guest OS's own update process is
  usually the single most disk-I/O-heavy thing it does).
- **Display overhead**: software-rendered `virtio-gpu` (`01` §2.5's
  default) is functional for desktop/office use, not for anything
  frame-rate-sensitive.

None of this is unique to Terem — it is inherent to hosted virtualization
generally, disclosed here rather than left for the operator to discover
mid-use.

### 4.2 GPU passthrough limits

Carried forward from `01` §2.5, restated here as a licensing/expectations
question rather than a pure architecture one: **most laptops cannot give a
guest a real GPU and keep a usable host display at the same time** — real
passthrough needs a second, dedicated GPU and IOMMU support most consumer
laptops don't have. Marketing this feature without that qualifier would be
the kind of overclaim `docs/design/bridge-trust-boundaries.md`'s discipline
exists to prevent. State it as: *"GPU passthrough is available on
compatible desktop hardware with a spare GPU and IOMMU support; on typical
single-GPU laptops, guests use software rendering — fine for office/dev
work, not for gaming or GPU-accelerated workloads."*

### 4.3 DRM / anti-cheat detecting the sandbox and refusing — by design, not a bug

The single closest parallel to Sloboda's "Play Integrity STRONG fails by
design" honesty: **VM-aware DRM and kernel-level anti-cheat systems
routinely detect that they are running inside a hypervisor (via CPUID
hypervisor bits, MSR probes, timing side-channels, or known virtual-device
signatures) and refuse to run, or refuse to grant full functionality.**
This affects both paths:

- **Guest Mode**: DRM video (studio/streaming-service DRM tiers analogous
  to Widevine L1), kernel-level anti-cheat (Easy Anti-Cheat, BattlEye,
  Denuvo-protected titles) commonly detect KVM/QEMU and refuse outright.
  This is the guest-OS-and-title vendors' own detection working as
  intended from their perspective — **not a Terem defect, and not
  something Terem attempts to spoof or defeat.** Spoofing hypervisor
  detection to bypass DRM/anti-cheat would cross from "honest sandbox" into
  "cheat-detection evasion," a line this design does not cross.
- **App Mode**: many titles' anti-cheat also detects Wine/Proton itself
  (independent of virtualization) and refuses to run. This is *why*
  upstream Proton ships an explicit, narrow allowlist for the small set of
  anti-cheat vendors that have opted in to Linux/Proton support
  (Easy Anti-Cheat and BattlEye both now support *some* titles under
  Proton, by the anti-cheat vendor's own choice, per-title) — most
  competitive titles still block Linux/Wine outright, and that is the
  honest default expectation, not the exception.

**The one-line disclosure to carry everywhere this matters, mirroring
Sloboda's own phrasing:** *"DRM and anti-cheat detecting a sandbox or a
compatibility layer and refusing to run is expected behavior, by the
vendor's own design — not a bug Terem can or will fix."*

### 4.4 Wine/Proton compatibility varies per app — not everything runs

App Mode is a **compatibility layer**, not an emulator or a guarantee. This
document deliberately does **not** publish a fabricated compatibility
percentage or a supported-app list — none exists without real testing, and
inventing one would be exactly the overclaim this document exists to
prevent. Instead, it adopts **WineHQ AppDB's own five-tier scale verbatim**
(per Architect 1's pass, `A-virtualization.md` §4.2) — a real, existing,
honest framework, not a new one invented for this product:

| Tier | Meaning | Roughly, what lands here |
|---|---|---|
| **Platinum** | Runs out-of-the-box, no tweaks, feature-complete | Many older/simpler Win32 productivity apps and utilities |
| **Gold** | Runs very well with minor, documented workarounds | Where most of the practical "run an old Windows app" value sits |
| **Silver** | Runs with significant, visible issues but usable | Apps with heavier GPU use or unusual installers |
| **Bronze** | Starts, but has major functional problems | Apps with deep OS integration (shell extensions, bundled kernel-mode components) |
| **Garbage** | Does not run at all | Kernel-mode-anti-cheat games, most DRM-gated software, hardware-dongle-locked enterprise apps |

**Concretely, what tends to work well:** productivity/office-class apps,
many older Win32 utilities, a large fraction of non-anti-cheat,
non-DRM Windows games (Proton/DXVK/VKD3D-Proton's daily-proven use case at
Steam Deck/Steam-on-Linux scale), CAD-lite/engineering tools without
hardware dongles. **What reliably fails, and why:** kernel-mode anti-cheat
(EasyAntiCheat/BattlEye in kernel mode, Vanguard) needs a Windows **kernel
driver**, which Wine categorically cannot provide — Wine has no kernel-mode
Windows driver model at all. Some anti-cheat vendors now explicitly
whitelist Proton/Steam Deck for specific titles, a real and improving
trend, but it is **per-title, vendor-opt-in**, never a Wine capability —
never state this as "Wine solved anti-cheat" (§4.3 already draws this line;
repeated here because it is the single easiest claim to accidentally
overstate). The honest product framing: *"Try App Mode first for one
Windows program — many popular apps run well. Check WineHQ AppDB's rating
for the specific app before trying, so expectations are set before, not
after. If it doesn't work, fall back to Guest Mode (`01` §4's decision
matrix). Postern does not guarantee any specific app runs under
Wine/Proton."*

**A prior, separate question this section does not resolve:** whether
Valve's own Proton build can be redistributed **outside Steam's own
distribution channel** at all is an open legal/practical question (`01`
§3.1, §7 item 8) — logically prior to the compatibility question above. If
that stays unresolved, the fallback is vanilla Wine plus independently-built
DXVK/VKD3D-Proton, both permissively licensed on their own terms, which
changes *what ships*, not the honest compatibility-varies message itself.

### 4.5 Reference-prototype / unaudited framing

Every claim in the Terem v2 doc family (`01`, `02`, this document) is
design-only, as stated in every header. Before any of this ships as a real
feature, the same maturity bar every other Postern product states for
itself applies: `written ≠ built`, `built ≠ booted`, `designed ≠ audited`.
Nothing here should be read as a working feature, a security control, or a
compatibility guarantee.

---

## 5 · Retiring v1's specific liability items — confirmed disposition

| v1 liability concern | v2 disposition |
|---|---|
| Firmware/Secure Boot/TPM/BitLocker on the **host** | **Dissolved** — guest firmware/TPM is virtual, guest disk encryption (if any) protects a file already sitting on the host's own LUKS volume (`01` §0.2, `02` §6). |
| Destructive host-disk wipe | **Dissolved** — no verb in v2 holds a host-disk handle (`01` §0.2, §6). |
| OS activation liability | **Narrowed, confirmed here (§1–§2)**: Postern is further from the vendor-license transaction in v2 than in v1, because there is no AI agent submitting the credential — the operator does it themselves, inside the guest, exactly as on real hardware. |
| DRM/anti-cheat refusing to run | **Not solved, honestly disclosed instead (§4.3)** — this was never a v1-specific problem to begin with; it is inherent to any sandboxed/translated execution and is handled the same way Sloboda handles Play Integrity: disclosure, never spoofing. |
| Driver/hardware coverage unevenness (v1 §5.8) | **Narrowed** — a guest's virtual hardware (OVMF, virtio devices) is a small, well-supported, uniform set Terem controls, unlike v1's "install onto whatever exotic physical hardware the client has" problem. Real physical-hardware driver coverage only matters again for the advanced GPU-passthrough opt-in (§4.2), which is explicitly non-default. |

---

## 6 · Honesty ledger — real vs. speculative, at a glance

| Claim in this document | Status |
|---|---|
| The user-brings-own-license model, and Postern's zero-custody role (§1) | **Real, direct extension of v1 §3.5's already-correct analysis**, strengthened by the removal of the AI-agent credential-submission step |
| Nominative trademark use rule (§1.3) | **Carried forward verbatim** from v1 §0. This is a stated policy, not currently covered by `check-trust-labels.sh` — that script's checks are the "Baba Yaga" trademark string and attestation-grade-word bleed onto non-attestable tiers, not the nominative-trademark-use rule; enforcement of this specific rule today is by review/discipline, not mechanical script |
| Terem's own license gate reusing the existing spine unmodified (§3) | **Real, shipped machinery** (`enterprise/licensing`) — the decision that no new token type is needed is this document's own judgment call, open to revision |
| VM overhead / GPU passthrough / DRM-anti-cheat / Wine compatibility caveats (§4) | **Honest, general, well-established facts about virtualization and Wine/Proton** — no fabricated numbers or compatibility claims; explicitly refuses to publish an unearned confidence figure |
| The v1-liability-retirement table (§5) | **This document's own synthesis**, cross-checked against `01`/`02`'s architectural claims |

*Design and scaffold only. UNAUDITED. Do not treat any claim in this
document as legal advice or a compatibility guarantee. Product name "Terem"
is proposed only, pending trademark clearance. Never "Postern Windows,"
"Postern Ubuntu," or "Postern RedHat." Windows/Ubuntu/RedHat are used
nominatively. Personal use of Terem follows Postern's free-forever doctrine
for Terem's own license gate only — it neither grants nor waives any target
OS vendor's own licensing, nor any individual app's own licensing under App
Mode. BLCH is worthless and is not a security. Not legal advice.*
