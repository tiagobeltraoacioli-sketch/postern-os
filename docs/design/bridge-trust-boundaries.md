<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Bridge trust boundaries — the canonical honesty architecture

**Role:** Architect A9 — cross-cutting trust-boundary & honesty-label owner across
Porog, NoporIS, and the Waydroid tier. **Status:** design/spec + enforcement
policy. **Non-negotiable:** every claim in code, UI, docs, and marketing must be
literally true AND keep `scripts/check-trust-labels.sh` green.

> **Why this document exists.** Honest labeling *is* the product. A single leak of
> an attestation-grade word onto an unaudited / non-attestable surface poisons the
> whole value proposition (holistic-VISION #5, the existential guardrail). The
> other nine architects design *mechanism*; A9 owns the *truth labels* so no
> mechanism can be described as more than it is. `check-trust-labels.sh` is the
> mechanical half — a heuristic tripwire, not a proof. This doc is the design half:
> what is true, how to phrase it so it stays true, and how to extend the tripwire.

---

## 0. The four postures (and the one they must never borrow)

There are **three shipping tiers** in scope, plus **one contrast anchor** that none
of the three inherits:

| # | Tier | Host | One-line true posture |
|---|------|------|----------------------|
| 1 | **Porog** — the *door* | Stock Android the user already owns (no OS replacement, no root) | **Key-attested device, not a measured-boot workspace.** Attests the *phone's* hardware keystore, never the container's contents. |
| 2 | **NoporIS** — the *bridge* | Same stock-Android device; joins two personas | **Separation, not privacy.** A default-closed, per-capability bridge; its Google-Play persona is the *less-private* side. |
| 3 | **Waydroid tier** (`apps/sloboda`) — the *escape hatch* | A GNU/Linux host Postern controls (postmarketOS / desktop), Android in LXC | **Non-attestable, never Seal-covered, UNTESTED.** Play Integrity STRONG fails by design. |
| — | **Contrast anchor: Postern OS / Postern Seal** | Nix-built, measured-boot OS | Attestable-by-design; `os_roothash`; reproducible. **A separate story. None of tiers 1–3 inherit it.** |

The cardinal error this architecture prevents: any of tiers 1–3 borrowing the
*measured-boot / Seal / reproducible-image* posture that belongs only to Postern OS.

---

## 1. Canonical trust-posture table (the single source of truth)

For each tier: what **is** attested, by what **mechanism**, what is **NOT** attested,
the **one honest qualifier** that must ride alongside, and the **forbidden overclaims**.

| | **Porog** (door) | **NoporIS** (bridge) | **Waydroid tier** (`apps/sloboda`) |
|---|---|---|---|
| **What IS attested** | The *phone's hardware keystore*: a StrongBox/TEE X.509 **key-attestation** chain rooted at a pinned anchor proves a hardware-backed key exists on this device. | **Nothing new.** NoporIS attests nothing of its own; it *reuses* Porog's key-attestation on the Porog persona and adds no attestation to the Google-Play persona. | **Nothing.** No attestation of any kind. |
| **Mechanism** | Android Keystore StrongBox key attestation (X.509 attestation extension), AOSP self-enrolled managed profile via `DevicePolicyManager`. | Dual-persona / managed-profile plumbing reused from Porog; a deny-by-default, per-capability consent gate between personas. | A Waydroid LXC container (full AOSP/Google userland) on a GNU/Linux host kernel; software keystore only. |
| **What is NOT attested** | The **workspace contents**, the OS, the boot state. Key attestation says "a key lives in hardware," **not** "this software is measured or sealed." A rooted host defeats it. | The **Google-Play persona** (it phones home to Google). The bridge crossing itself. Separation is a policy boundary, not a cryptographic attestation of privacy. | **Everything.** The Android image is mutable state pulled at `waydroid init`; `os_roothash` says nothing about it. No hardware TEE keymaster; unlocked bootloader on most devices. |
| **The one honest qualifier (must ride alongside)** | **"key-attested device, not a measured-boot workspace"** — plus: *hardened, not anonymous*; *a rooted host defeats it*; *never "Postern OS."* | **"separation, not privacy"** (on the Google side) — plus: *the Google persona is the less-private side*; *deny-by-default*; *a rooted host defeats the separation*; *never "Postern OS."* | **"non-attestable escape hatch, not covered by the Postern Seal"** — plus: *Play Integrity STRONG fails by design*; *UNTESTED until real aarch64 hardware*; *default-safe / bridge default-closed*; *never "Postern OS."* |
| **Forbidden overclaims** | "attested workspace / attestable workspace," "measured-boot," "Seal-covered," "tamper-proof," "reproducible," "anonymous," "Postern OS." | "private" (unqualified, re: the Google side), "attested bridge," "Google-Play-safe," any claim the crossing is cryptographically enforced, "Postern OS." | **Every** attestation-grade word affirmatively (`attestable/attested/hardware-backed/strongbox/tamper-proof/…`), "Seal-covered," "Play Integrity STRONG passes," "tested / it boots," "secure" unqualified, "Postern OS." |
| **In `NONATTEST_PATHS`?** | **No** — "key-attested" is a *true* claim for Porog, so a blanket ban would be wrong. Governed instead by the **qualifier-companion rule** (§2.2). | **No** today — **coverage gap, see §5.** NoporIS surfaces (`apps/noporis-*`) can currently use attestation words unchecked. | **Yes** — `apps/sloboda` + `apps/sloboda-gate`. Affirmative attestation words hard-fail. |

**Reading the table:** Porog is the *only* one of the three that legitimately owns
an attestation word ("key-attested"), and only for the **device key**, never the
workspace. NoporIS and Waydroid own **none** — they may name attestation only to
**deny** it.

---

## 2. Label rules — how to stay true AND pass `check-trust-labels.sh`

The script's two BLOCKING checks are:
1. **CRITICAL 1** — the "Baba Yaga" trademark string must not appear in shipping
   surfaces (`apps/crates/site/desktop/pmos-overlay`, non-`.md`). Ship as
   Yagabona/Izbushka.
2. **CRITICAL 2** — a `FORBIDDEN` attestation-grade word on a `NONATTEST_PATHS`
   surface, on a line **not** negated by the current or immediately-preceding line
   and **not** an inline contrast/reference to the attestable tier.

`FORBIDDEN` = `attestable | attested | tamper-proof | hardware-backed | secure
enclave | strongbox | military-grade | bit-for-bit reproducible | unhackable |
NSA-proof | zero-knowledge-proof-of`.

### 2.1 The NEGATION / CONTRAST phrasing pattern (how a non-attestable tier may name attestation only to deny it)

On a `NONATTEST_PATHS` surface a `FORBIDDEN` word is **suppressed** (allowed) only
if the same line or the line directly above contains a **NEGATION** or **CONTRAST**
token. Write the disclaimer so the negation is adjacent — never leave a bare
attestation word hoping context two lines up saves it.

- **NEGATION tokens:** `not `, `no `, `never`, `non-`, `un-`, `isn't`, `aren't`,
  `cannot`, `can't`, `without`, `lacks`, `fails`, `refus…`. Markdown emphasis
  (`* _ \``) and `!=` / `≠` are neutralized first, so `**not**` and `signed !=
  attested` both read as negations.
- **CONTRAST tokens:** `postern os`, `= false` / `"false"` / `: false`, `only`,
  `leave`, `the attestable`, `less-`, `not part`, `elsewhere`, `is the
  requirement`, `strongbox / keystore`, `do not`, `don't`, `no … guarantee`,
  `bleed`, `poison`, `mget`.

**Correct (passes + true):**
- `Play Integrity STRONG will fail … cannot reach STRONG.` — `cannot` negates.
- `Do not treat an Android app here as attested.` — `Do not` (CONTRAST) + `not`.
- `signed **≠** attested` — neutralized `≠` → `not`.
- `The attestable path is the Nix-built "Postern OS" family, only.` — CONTRAST
  (`the attestable`, `postern os`, `only`).
- `key-attested device, **not** a measured-boot workspace` — `not` on-line.

**Wrong (bleeds → CRITICAL 2 fail, and is a lie):**
- `StrongBox-backed keystore protects the workspace.` — affirmative, no negation.
- A heading `## Hardware-backed attestation` with the disclaimer three lines below.

**Rule of thumb:** on tiers 2 and 3, put the negation **in the same sentence** as
the attestation word. Never separate the claim from its denial.

### 2.2 The qualifier-companion rule (Porog's special case)

Porog is *not* in `NONATTEST_PATHS` because "key-attested" is true for it. But
"key-attested" without its qualifier silently implies workspace/measured-boot
attestation — the exact overclaim. Therefore:

> **Wherever `key-attested` (or `key attestation` / `StrongBox … attest…`) appears
> on a Porog or NoporIS surface, the qualifier "not a measured-boot workspace"
> (or "not measured-boot") MUST appear within the same paragraph / ±3 lines.**

This is a **positive-companion** requirement, the inverse of CRITICAL 2's ban. It is
proposed as a new CI check (§5, check C).

### 2.3 The measured-boot / Seal firewall (all three tiers)

None of the three tiers may **affirmatively** claim `measured-boot`, `Postern
Seal`, `Seal-covered`, `os_roothash`, or `reproducible` about itself. These belong
to Postern OS only. They may appear **only** in a contrast that hands them back to
Postern OS ("*not* a measured-boot workspace," "*not* covered by the Postern
Seal," "the attestable path is Postern OS, only").

### 2.4 The "less-private / separation-not-privacy" rule (NoporIS)

Any surface describing the Google-Play persona must label it the **less-private**
side and, where it says "separation," must not let "separation" be read as
"privacy." Canonical phrasing: **"separation, not privacy"** and **"it phones home
to Google."** Never "private Google persona," never "Play-safe."

### 2.5 The default-closed rule (NoporIS + Waydroid bridge)

The bridge/consent state is **default-closed**: any value but the literal `enabled`
is **off**. Code must *read* the consent-gate toggle read-only and never default it
open. UI copy must not describe the bridge as "on by default" or "always
available." (The Waydroid wrapper already implements this; `paw-lib.sh` treats
anything but `enabled` as off.)

### 2.6 The UNTESTED / signed≠attested rule (Waydroid + pmOS apk)

Where behaviour has not run on real hardware, say **UNTESTED** / **never
device-booted**. "Signed" is not "attestable"; "built + signed" is not "it boots";
"QEMU-validated" is not "hardware-tested." Keep these three inequalities intact
everywhere the artifacts are described.

### 2.7 Naming rule

Ship "Baba Yaga" IP as **Yagabona / Izbushka**, never the registered string in a
shipping (non-`.md`) surface. "Porog" and "NoporIS" are **proposed names, pending
trademark clearance** — always so labelled. None of the three is ever **"Postern
OS."**

---

## 3. Per-tier threat model (what each boundary protects against — and what it does NOT)

### 3.1 Porog (the door)
- **Protects against:** casual app-level snooping across the personal↔work
  boundary (separate FBE keys, own lock, SELinux profile boundary); a lost/seized
  phone proving key provenance (hardware key attestation); rogue keyboards / screen
  capture inside the profile (`setPermittedInputMethods`, `setScreenCaptureDisabled`);
  clear-net leakage from the profile (`setAlwaysOnVpnPackage` Tor lockdown).
- **Does NOT protect against:** a **rooted / compromised host OS** (defeats the
  whole profile boundary); a **malicious or backdoored OS image** (Porog does not
  measure or seal the OS — that's Postern OS); traffic-analysis deanonymization
  (*hardened, not anonymous*); anything claiming the *workspace* is attested (only
  the *device key* is).

### 3.2 NoporIS (the bridge)
- **Protects against:** accidental data flow between the private persona and the
  Google-Play persona (deny-by-default, per-capability crossing); carrying two
  physical devices (one phone, two worlds); GMS phoning home *from the private
  side* (Google lives only on the less-private persona).
- **Does NOT protect against:** Google seeing everything on the **Google-Play
  persona** (that side is *less-private* by construction — separation, not
  privacy); a **rooted host** (defeats the separation); an attestation claim about
  the crossing (the gate is a policy boundary, not a cryptographic proof of
  privacy). NoporIS adds **no new attestation**.

### 3.3 Waydroid tier (`apps/sloboda`, the escape hatch)
- **Protects against:** nothing cryptographically. Its only guarantees are
  operational: **default-closed** bridge (reads consent read-only), a **kill-switch**
  that stops the container and clears session runtime state, and a **VANILLA
  (Google-free) default** image so Google is opt-in, never hardcoded.
- **Does NOT protect against:** anything requiring attestation — **Play Integrity
  STRONG fails by design** (banking / Wallet / Widevine L1 refuse to run); the
  container is a **large opaque trust surface** next to the wallet ("entering
  Android = data leaves the sealed base"); it is **not Seal-covered**
  (`os_roothash` says nothing about it); and it is **UNTESTED** — nothing here has
  ever booted an Android container. Keep secrets **out** of Android apps here.

---

## 4. Pre-ship honesty checklist (run before any Porog/NoporIS/Waydroid surface merges)

For **every** new or changed code / UI / doc / marketing string:

- [ ] `scripts/check-trust-labels.sh` is **green** (`critical: 0`). Run `STRICT=1`
      and review every WARN.
- [ ] No attestation-grade word on a `NONATTEST_PATHS` surface without an adjacent
      NEGATION/CONTRAST (same line or line above) — see §2.1.
- [ ] Every `key-attested` on a Porog/NoporIS surface has "**not a measured-boot
      workspace**" within ±3 lines (§2.2).
- [ ] No tier claims `measured-boot` / `Postern Seal` / `Seal-covered` /
      `os_roothash` / `reproducible` about **itself** (§2.3).
- [ ] NoporIS Google persona labelled **less-private** + **"separation, not
      privacy"**; never "private"/"Play-safe" (§2.4).
- [ ] Bridge/consent described as **default-closed**; code reads the toggle
      read-only and cannot default it open (§2.5).
- [ ] Unproven behaviour labelled **UNTESTED / never device-booted**; the three
      inequalities (`signed ≠ attestable`, `built+signed ≠ boots`, `QEMU ≠
      hardware`) intact (§2.6).
- [ ] No "Baba Yaga" in a shipping (non-`.md`) surface; "Porog"/"NoporIS" carry
      **"proposed name, pending trademark clearance"**; nothing called **"Postern
      OS"** (§2.7).
- [ ] `apps/crates/site` all agree — the site `build.js` badge/copy for the tier
      matches this table (no surface says more than the strictest one).
- [ ] Every affirmative security adjective ("secure," "hardened," "private") is
      qualified or negated; "hardened, not anonymous" preferred over bare
      "hardened."

---

## 5. Proposed additions to `check-trust-labels.sh` (close the gaps)

The current script covers `pmos-overlay`, `apps/sloboda`,
`apps/sloboda-gate`. Four gaps let future Porog/NoporIS code silently
overclaim. Proposed, in priority order:

**A. Add the NoporIS/Porog glue+UI dirs to a bounded non-attestable scan.**
`apps/noporis-switcher`, `apps/noporis-*-glue`, `apps/noporis-gate`,
`apps/porog-tor-glue` currently sit **outside** `NONATTEST_PATHS`, so an affirmative
"attestable/hardware-backed workspace" there would not fail CI. Because Porog
legitimately says "key-attested," do **not** blanket-ban these — instead pair the
scan with check C below. Concretely: add these paths to a new `QUALIFIED_PATHS`
array scanned by `scan_nonattest` **but** with `key-attest…` removed from
`FORBIDDEN_LC` for that pass (so the true claim survives) while
`attestable-workspace | measured-boot | seal-covered | tamper-proof | hardware-backed`
still hard-fail.

**B. Extend `FORBIDDEN` with the Seal/measured-boot family.** Add
`measured-boot | measured boot | seal-covered | seal covered | os_roothash | postern seal`
to the forbidden set for all non-attestable + qualified paths. These are the exact
words the three tiers must never claim about themselves; today `measured-boot`
passes freely. (Keep the existing CONTRAST `postern os` token so honest "*not* a
measured-boot workspace / the attestable path is Postern OS, only" disclaimers stay
suppressed.)

**C. New POSITIVE check — qualifier-companion for `key-attested`.** For every
Porog/NoporIS surface line matching `key-attest…`, require `not .*measured-boot` (or
`not a measured-boot workspace`) within a ±3-line window; else FAIL. This catches
the highest-frequency real overclaim: dropping the qualifier and letting
"key-attested" imply workspace attestation. Sketch:

```bash
# CRITICAL 3 — 'key-attested' without its 'not measured-boot' qualifier (BLOCKING)
QUALIFIED_PATHS=(apps/porog-tor-glue apps/noporis-switcher apps/noporis-signer-glue \
                 apps/noporis-bridge-glue apps/noporis-gate apps/noporis-tor-glue)
for p in "${QUALIFIED_PATHS[@]}"; do
  [ -e "$p" ] || continue
  grep -rilIE $EX 'key[ -]?attest' "$p" 2>/dev/null | while IFS= read -r f; do
    awk '
      { L[NR]=tolower($0) }
      END {
        for (i=1;i<=NR;i++) if (L[i] ~ /key[ -]?attest/) {
          ok=0
          for (j=i-3;j<=i+3;j++) if (j>=1 && j<=NR && L[j] ~ /not[^a-z]*measured|not a measured|not[^a-z]*measured-boot/) ok=1
          if (!ok) printf "%s:%d: key-attested without \"not measured-boot\" qualifier\n", FILENAME, i
        }
      }' "$f"
  done
done
```

**D. New BLOCKING string check — "Play Integrity STRONG passes" and "Seal-covered"
on tiers 1–3.** A grep that FAILs on affirmative `STRONG (passes|works|succeeds)` or
`seal[- ]covered` unless negated on the line — mirrors CRITICAL 2's structure. The
Waydroid README's truth is "STRONG **will fail**"; this locks it.

**E. Cross-surface consistency (advisory WARN).** A check that the site
`build.js` badge text for each tier contains the required qualifier tokens
("proposed name," "non-attestable," "separation, not privacy," "not measured-boot")
per tier — so the public marketing can't drift looser than the in-repo docs.

Land **A–C** as blocking (they close real overclaim paths); **D** as blocking once
the string set is agreed; **E** as WARN.

---

## 6. Summary — the invariant A9 enforces

> **Porog** attests the *phone's key*, never the workspace — "key-attested device,
> not a measured-boot workspace." **NoporIS** sells *separation, not privacy*, is
> *default-closed*, and attests nothing new. **The Waydroid tier** is a
> *non-attestable, never-Sealed, UNTESTED* escape hatch where STRONG fails by
> design. **The measured-boot Postern OS / Postern Seal is a separate story none of
> the three inherit.** Any tier may name attestation only to **deny** it (adjacent
> NEGATION/CONTRAST), except Porog's true "key-attested" which must always carry its
> "not a measured-boot workspace" qualifier. Keep `check-trust-labels.sh` green;
> land the §5 additions so future code cannot silently overclaim.
</content>
</invoke>
