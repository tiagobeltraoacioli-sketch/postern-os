<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- Copyright (c) Postern Labs and Postern community contributors -->

# OS Portal v2 (Terem) — the permissive-license decision, resolved

**Status: DESIGN DECISION, not a legal opinion.** This closes the open item
`A-virtualization.md` §8.1 left as "needs a real counsel/`deny.toml`-class
pass, not an inferred yes." It is Postern Labs' own considered, honest
application of the repo's existing rule — the same non-legal-advice posture
every other license call in this tree already carries
(`POSTERN-TELEPHONY.md` §7, `POSTERN-CLOUD.md` §8). Get real counsel before
shipping any of the "in" components below. `written ≠ built`,
`designed ≠ audited`.

**The rule, restated exactly once:** `BLOCH-SIS-LINUX.md` §2.4 /
`POSTERN-CLOUD.md` §8 — **permissive-only, no AGPL/GPL/LGPL in the shipped
stack.** MPL only as unmodified aggregation. AGPL/GPL/LGPL = no fork, no
embed, no link.

---

## 0 · The question this document actually answers

`A-virtualization.md` §0 correctly identified that the existing GPL exception
(ModemManager/oFono/mmsd-tng/callaudiod, `POSTERN-TELEPHONY.md`) does not
*automatically* transfer to QEMU/Wine, and flagged the precise gap:

> is "external GPL/LGPL process, invoked via its own documented
> protocol/CLI, never linked" an exception this repo is willing to extend
> from *already-present system daemons* to a *newly-bundled-by-us* binary?

That gap is real, and it is not primarily a copyright-law question — it's a
**self-imposed brand-purity question**. Legally, driving an unmodified GPL
binary over a socket/CLI boundary (never linking, never forking) is
well-settled, low-risk practice: GPLv2 §2's own "mere aggregation" clause
says combining unmodified GPL software with other software on the same
distribution medium does not bring the other software under GPL, and this
is exactly how every Linux distribution ships thousands of GPL binaries
alongside proprietary and permissive software with no infection. **The
telephony precedent works for a different, narrower reason than "fork/exec
is always safe":** ModemManager et al. are **not actually part of "Postern's
shipped stack" at all** — they are base-OS/kernel-adjacent components that
exist on the phone regardless of what Postern builds (`POSTERN-CLOUD.md` §8's
own words for the kernel: *"not a distributed component of ours"*).

**QEMU and Wine fail that specific test on its face.** Nothing about a
NixOS desktop requires QEMU or Wine to exist — Postern would have to
deliberately add `pkgs.qemu`/`pkgs.wine` to a Nix derivation *specifically
to build Terem*. If that derivation is part of the default, attested
`os_roothash`-measured closure, the GPL/LGPL binaries are unambiguously
**"in the shipped stack"** in the plain, literal sense the rule uses — bytes
on the sealed disk image — regardless of how cleanly they're driven at
runtime. The "external unforked process" argument answers *"would this
infect Postern's own code with copyleft"* (no); it does not answer *"is this
still true — no GPL/LGPL/AGPL in the shipped stack — as a factual claim
about the image"* (no, if baked into the default build).

That is the actual fork in the road, and this document resolves it.

---

## 1 · Decision, per component

| Component | License | Decision | Ships in the default attested image? |
|---|---|---|---|
| **QEMU** | GPL-2.0 | **Not bundled by Postern, default build stays clean. Opt-in only** (§2). | **No.** |
| **libvirt** | LGPL-2.1 | **Out, full stop, no exception considered.** Confirms `A-virtualization.md` §0's existing call. | N/A — never shipped, never enabled. |
| **Wine** | LGPL-2.1 | **Not bundled by Postern, default build stays clean. Opt-in only** (§2), same shape as QEMU. | **No.** |
| **Proton (Valve's build)** | LGPL-2.1 + mixed bundled components | **Out — not shipped at all, independent of the license question.** Redistribution outside Steam's own channel is a rights/trademark question this document does not resolve, and there is a clean fallback (§3) that sidesteps it entirely. | **No.** |
| **Cloud Hypervisor** | Apache-2.0 | **In. Default, in-box VMM for the guest shapes it currently handles well** (headless/Linux-guest, SNP/TDX-relevant). | **Yes.** |
| **crosvm** | BSD-3 / Apache-2.0 | Noted as available, not adopted — Cloud Hypervisor is the better-fit permissive option for this repo's own SNP/TDX interest; not pursued further here. | N/A. |
| **virtio-win driver ISO** | Mixed (Red Hat-maintained, per-driver) | Unchanged from `A-virtualization.md` §1.4 — needed only if/when a Windows guest runs under the opt-in QEMU path; re-verify per-driver licenses before bundling, same `deny.toml` discipline as everything else. | Only if the QEMU opt-in is enabled *and* a Windows guest is created. |

---

## 2 · Why "opt-in, never in the default closure" is the honest answer for QEMU and Wine

This is the concrete resolution, not another deferral:

- **Postern's default, published, attested Terem build ships zero
  GPL/LGPL/AGPL code.** The claim "permissive-only, no AGPL/GPL/LGPL in the
  shipped stack" stays **literally true** for the artifact Postern actually
  distributes and measures (`os_roothash`), with no asterisk needed.
- QEMU and Wine become an **operator-initiated add-on**, mirroring the
  doctrine `03-license-honesty.md` §1 already established for the guest OS
  itself ("Postern never provides, bundles... Terem's role in that
  transaction is zero"). Extend that one layer down: **Postern's role in
  the operator acquiring a GPL/LGPL runtime is also zero.** The operator
  either (a) already has `qemu`/`wine` on their system via their own package
  manager, or (b) flips an explicit NixOS module toggle —
  `postern.terem.enableQemu` / `postern.terem.enableWine`, `lib.mkEnableOption`,
  same shape as every other opt-in module this repo already uses — which
  rebuilds *their own machine's* closure to include it. Postern's Tauri
  shell then does exactly what it already does for `bloch`
  (`resolve_node_binary`'s pattern): resolve, canonicalize, and verify the
  binary before spawning it as a plain `Command` — it never links `libwine`
  or a `libvirt`-class client library, and the QMP/CLI boundary is exactly
  the shape `A-virtualization.md` §1.5 already designed.
- **This is not a hollow distinction.** A never-enabled Nix option adds
  zero bytes to a fresh install's disk image and zero lines to its
  `os_roothash` measurement. An operator who *does* flip the toggle gets a
  **different, honestly different, measurable image** — which is a feature,
  not a gap: `POSTERN-CLOUD.md` §7's own discipline ("an update is a new
  image... never an in-place mutation") already assumes different
  build/config variants produce different measurements, and an attestation
  report or transparency panel can truthfully say whether a given running
  Postern machine opted into the GPL VMM/compat-layer add-on. The host
  stays exactly as attestable as `A-virtualization.md` §1.6 already claims;
  this just adds one more honestly-labeled variant axis to what "the host"
  can mean.
- **Precedent this mirrors, stated plainly so it isn't oversold:** this is
  the same posture Fedora Workstation takes toward RPM Fusion, or Debian
  toward `contrib`/`non-free` — the distribution's own default-shipped
  claim is about what it ships **by default**, not a claim that a user can
  never add anything else. Postern's claim should be phrased with that
  same precision: *"Postern OS's default, attested build is 100%
  permissively licensed. Terem's full-VM and Wine/Proton features are
  opt-in, pull GPL/LGPL software from nixpkgs under the operator's own
  explicit action, and are clearly labeled as such."* Never *"Postern
  doesn't use GPL"* unqualified — that would stop being true the moment the
  opt-in module exists in the repo at all, whether or not any machine has
  it enabled.

---

## 3 · Proton — resolved independently of the LGPL question

Even setting the GPL/LGPL question aside entirely, **Valve's Proton build is
not shipped, and this document recommends against pursuing standalone
Proton redistribution at all.** The blocker is a **rights/trademark/build-
provenance** question (is Valve's specific compiled build, assembled for
the Steam Linux Runtime container, redistributable outside that channel at
all?), not a copyleft one, and it is not worth resolving because a clean
fallback exists: **vanilla Wine + independently-built DXVK (zlib — clean,
no exception needed at all) + VKD3D-Proton (LGPL-2.1 — same opt-in,
never-bundled treatment as Wine itself, §2).** An operator who already has
Steam installed and wants Valve's specific Proton build can point Terem at
their own existing Steam/Proton install (again, the operator's own prior
action, not Postern's distribution) — same "bring your own" doctrine,
applied consistently.

---

## 4 · Cloud Hypervisor — feasibility, stated honestly

**Decision: yes, adopt as the default in-box VMM, scoped to what it
currently does well; keep prototyping the rest before promising it.**

- **Fits cleanly, no exception needed.** Apache-2.0, rust-vmm, genuinely
  linkable/embeddable under the repo's own rule with zero interpretive
  work — the one VMM option in this whole document that requires no
  judgment call at all.
- **Fits the SEV-SNP/TDX need directly**, which is not a coincidence —
  Cloud Hypervisor already matters to this repo for Chiostro
  (`os/cloud.nix`, `POSTERN-CLOUD.md`), and it has first-class SNP/TDX
  guest support. Standardizing on it for Terem's headless/Linux-guest case
  reuses machinery `postern-seal-companion` has already vector-tested,
  rather than adding a second VMM abstraction for no reason.
- **The honest gap, unchanged from `A-virtualization.md` §1.1: guest
  graphics and Windows-guest maturity trail QEMU/KVM today.** No SPICE (not
  needed — SPICE is LGPL and already ruled out anyway, §8 of
  `POSTERN-CLOUD.md`), virtio-gpu support is newer/narrower, and Windows
  guest support is less proven. **This document does not claim Cloud
  Hypervisor is ready for a graphical Windows 11 desktop guest today** —
  that remains an open, evidence-based question, not a settled yes.
- **What this means concretely for Terem's roadmap:** v1's default,
  permissive-only, always-shipped guest-runtime path is **Cloud
  Hypervisor, scoped to Linux/headless-shaped guests** (the case it already
  demonstrably handles). **"A graphical Windows 11 guest" is real product
  value this repo wants, and today the only mature way to hit it is the §2
  opt-in QEMU path** — that is a genuine, load-bearing consequence of this
  decision, not a footnote: if Cloud Hypervisor's Windows-guest/graphics
  story matures enough before ship, the opt-in tier shrinks or disappears;
  if it does not, "run Windows 11 in Terem" ships as an **opt-in, clearly
  GPL-labeled, advanced-user feature** rather than a default headline
  capability. Recommend the time-boxed prototype `A-virtualization.md` §8.2
  already asked for, now explicitly to decide *this*, not a generic
  maturity check.

---

## 5 · The honest risk section

- **The GPL-mere-aggregation argument is well-established distro practice,
  not litigated case law.** Real risk of a successful copyleft-infection
  claim against Postern's own permissive code is low by any normal
  industry standard (it is, again, exactly what every major Linux distro
  does), but "low" is not "zero," and if Postern's own opt-in Nix module
  ever moves from *pure orchestration of an operator-fetched binary* toward
  *Postern building and redistributing its own QEMU/Wine derivation*, get
  real counsel before that ships — the fork/exec boundary is doing real
  work here and should not quietly erode.
- **"Opt-in, never in the default closure" shifts real friction onto users,
  not just a paperwork fix.** A user who wants "run Windows 11" as
  advertised has to take an extra, disclosed step (flip a Nix option and
  rebuild, or already have `qemu`/`wine` installed) before Terem's headline
  feature works. This is consistent with the friction `03-license-honesty.md`
  §1.2 already accepts for typing your own Windows key, but it is a real,
  user-facing cost, and product copy must disclose it with the same
  plainness as the DRM/anti-cheat caveats in `03-license-honesty.md` §4 —
  not softened into "advanced settings" language that hides why the toggle
  exists.
- **"Is an opt-in NixOS module itself part of 'the shipped stack'?" is the
  one remaining interpretive ambiguity this document cannot fully close on
  its own.** Read narrowly (what ships/measures on a machine by default),
  the opt-in module is clean. Read broadly (what's in Postern's own git
  repo / build recipes at all, whether or not any real machine enables it),
  a reasonable person could still object that a first-class, one-toggle,
  well-supported path to GPL software is a materially different posture
  than never having built that path. This document's judgment is the
  narrow reading is correct and consistent with how the rest of this repo
  already treats variant builds (`POSTERN-CLOUD.md` §7's per-image
  measurement discipline presumes different opt-in profiles are different,
  honestly-labeled images) — but per `A-virtualization.md` §8.1's own
  standard, this deserves an **explicit PMO/counsel yes, not an inferred
  one**, before the opt-in modules ship.
- **Cloud Hypervisor's Windows-guest/graphics gap is the single biggest
  unresolved variable in this whole document.** This decision's cleanliness
  for the *default* build depends on that gap staying real (i.e., Windows
  guests staying an honestly-labeled opt-in tier). If product pressure
  pushes to promise "Windows 11 works out of the box" before Cloud
  Hypervisor's guest-graphics story matures, the only way to deliver that
  under this repo's own rule is the §2 opt-in QEMU path, made prominent
  rather than kept as an edge case — which is a product-positioning
  decision for the lead architect/PMO, not something this document can
  resolve by itself.
- **Proton's rights question (§3) is genuinely unresolved, not merely
  deprioritized.** This document sidesteps it via the vanilla-Wine+DXVK+
  VKD3D-Proton fallback rather than closing it; if standalone Proton
  redistribution is ever revisited, it needs its own dedicated legal pass
  independent of this document's GPL/LGPL analysis.

---

*Design decision only. UNAUDITED. This is Postern Labs' own honest,
best-effort application of this repo's existing, self-imposed licensing
rule — it is not a legal opinion, and every "in" component here (Cloud
Hypervisor's adoption, the opt-in QEMU/Wine module shape) should get a real
license-counsel/`deny.toml`-class pass before anything ships, exactly as
`A-virtualization.md` §8.1 already asked for. Never "Postern Windows,"
"Postern Ubuntu," or "Postern RedHat." BLCH is worthless and is not a
security. Not legal advice.*
