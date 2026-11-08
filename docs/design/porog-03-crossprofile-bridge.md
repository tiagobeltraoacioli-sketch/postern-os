<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Porog A3 — cross-profile data boundary & consent-gated bridge policy

**Status: DESIGN / reference-prototype. UNAUDITED. No security claim.**
Nothing here has been built into a shipped container or run on a device. This is
the **A3 enforcement contract**: *what may cross the work↔personal boundary in
Porog, and how a deny-by-default consent gate turns each explicit user grant into
concrete `DevicePolicyManager` policy — and slams it all shut on the kill-switch.*

> ## ⚠ HONESTY HEADER — read before trusting anything here
>
> - **Porog attests the phone, not the workspace.** Any StrongBox key-attestation
>   chain proves a *hardware-backed device key* — it is a **key-attested device,
>   NOT a measured-boot workspace**. Nothing in this document measures or seals the
>   managed profile's contents.
> - **Stock, un-rooted Android; self-enrolled DPC.** Porog's isolation is
>   **Android's own** managed-profile mechanism, configured by an unprivileged
>   profile-owner app (`ACTION_PROVISION_MANAGED_PROFILE`, the Shelter/Island
>   path). No root, no OS replacement, no EMM server. It is **never "Postern OS."**
> - **A rooted / unlocked / kernel-compromised host defeats the boundary.** The
>   cross-profile controls here are userland framework policy, only as strong as
>   the kernel and framework underneath them.
> - **Default-SAFE: the bridge is CLOSED unless an explicit consent state says
>   otherwise.** This mirrors the Waydroid wrapper's read-only gate
>   (`bin/paw-lib.sh` `paw_bridge_enabled`: anything but a literal `enabled` = off).
>   Here: any value that is not exactly `true` — missing file, unparseable file,
>   unknown version, missing field — collapses to **full-deny + not-consented**.
> - **The DPC governs only the profile it owns.** Porog can gate what crosses *at
>   the managed-profile edge*; it **cannot police what the personal side does with
>   data once it has crossed**, and it **cannot claw back bytes already copied**.
>   The kill-switch closes the door for *future* flows and revokes *live* grants —
>   it does not un-send what already went.
> - **Respect Google/Android licenses.** No GMS redistribution (the user brings
>   their own Google install on the Google-Play persona), no Play-Integrity /
>   SafetyNet circumvention. Android and Google Play are named nominatively only.
> - **UNAUDITED reference-prototype.** The DPC and consent UI described here do not
>   exist yet (UNTESTED). The coin is worthless and is **not a security**. Personal
>   use is free. **This is not legal advice.**

---

## 0. Where this sits (products & seams)

Two folklore shapes, one shared consent kernel:

- **Porog — the *door*** (`apps/izbushka` + the stock-Android managed-profile
  container): the guarded threshold. **This document owns Porog's cross-profile
  *enforcement* side.**
- **NoporIS — the *bridge*** (`apps/noporis-gate`, A4/A5): the guarded crossing
  between a near/clean persona and a far Google-Play persona. NoporIS owns the
  **consent surface** (the levers the user throws, the UI that *writes* state).

**The seam (this is the whole point of A3):** NoporIS *presents and writes* which
capabilities the user hands across; **Porog *reads and enforces*** by mapping each
open crossing onto concrete `DevicePolicyManager` (DPM) policy. This mirrors the
existing `porog-tor-glue` pattern, where the gate's `egressAllowed()` and the
crate's `egress_decision()` are **the same fail-closed rule on the two sides of
the seam**. Same discipline here: one gate state file is the single source of
truth; NoporIS writes it, Porog's reconcile loop makes the framework match it.

Grounding read: `apps/sloboda/README.md` (default-safe consent-gate),
`apps/sloboda/bin/paw-lib.sh` (read-only literal-`enabled` bridge check),
`docs/design/design-android-container.md` (managed-profile / self-enrolled-DPC
mechanism), `apps/noporis-gate/` and `apps/sloboda-gate/` (the
deny-by-default gate-kernel pattern this doc extends).

---

## 1. The boundary model

### 1.1 Topology

```
┌────────────────────────────────────────────────────────────────────────────┐
│  ONE stock Android phone, un-rooted, self-enrolled                          │
│                                                                              │
│   NEAR / private persona                    FAR / Google-Play persona        │
│   (personal user, user 0)                   (managed profile, user N)        │
│   · sealed wallet + keys live here          · Porog DPC = PROFILE OWNER      │
│   · outside the DPC's control               · phones home to Google          │
│                                             · the LESS-PRIVATE side          │
│                    ╎                                    ╎                     │
│                    ╎  ◀── cross-profile boundary ──▶    ╎                     │
│                    ╎  default: FULLY PARTITIONED        ╎                     │
│                    ╎  · no intents resolve across       ╎                     │
│                    ╎  · copy/paste BLOCKED              ╎                     │
│                    ╎  · contacts/caller-ID/calendar OFF ╎                     │
│                    ╎  · no shared files, no widgets     ╎                     │
└────────────────────────────────────────────────────────────────────────────┘
```

Honest note on the persona↔profile mapping: on stock Android the **DPC is
profile owner of the *managed profile* only**; the personal user (user 0) is
outside its authority. Porog therefore contains the **Google-Play persona inside
the managed profile** it owns, and enforces the partition *at that profile's
edge*. It can lock down what leaves/enters the managed profile; it **cannot**
impose policy on the personal side. That asymmetry is a boundary property, not a
bug to paper over.

### 1.2 Direction is first-class

Every cross-profile grant carries a **direction**, encoded by the framework flags
on `addCrossProfileIntentFilter(admin, filter, flags)`:

- `FLAG_PARENT_CAN_ACCESS_MANAGED` → personal → managed (data flows **into** the
  Google-Play side).
- `FLAG_MANAGED_CAN_ACCESS_PARENT` → managed → personal (data flows **out of** the
  Google-Play side, into the private side).

Default-safe = **neither flag set, no filter installed** (`direction: "none"`). A
crossing that is "open" is meaningless without a direction; the gate stores it,
Porog enforces it, and the two directions are independently grantable and
independently revocable.

### 1.3 What each direction *means* for privacy (the honest framing)

- **personal → Google-Play (p2w):** private data moves to the side that **phones
  home to Google**. This is the riskier flow; even when the user opens it, it is
  user-mediated and per-item, never background/bulk.
- **Google-Play → personal (w2p):** potentially Google-tainted data is imported
  into the private side.
- **Neither direction is "private."** NoporIS sells **separation, not privacy** on
  the Google side. Porog *enforces the partition*; it **cannot make the Google
  side private**. Opening any crossing is a deliberate, disclosed trade.

---

## 2. Cross-profile capability map — what is safe to expose, what stays closed

Porog's DPC enforces the boundary through the profile-owner DPM surface. Every
row **defaults to the closed/most-restrictive state**; a crossing moves only by an
explicit, disclosed, individually-revocable grant in the gate state.

| Capability | Framework mechanism (profile owner) | Default (closed) | On explicit consent | Exposure class |
|---|---|---|---|---|
| **App-launch / intents across** | `addCrossProfileIntentFilter(admin, IntentFilter, flags)` / `clearCrossProfileIntentFilters(admin)` | **no filters installed** | install exactly **one narrow filter** (specific action, e.g. `ACTION_SEND`) with **only** the granted direction flag | user-mediated |
| **Clipboard copy/paste** | `UserManager.DISALLOW_CROSS_PROFILE_COPY_PASTE` via `addUserRestriction` / `clearUserRestriction` | **restriction ON** (paste blocked) | `clearUserRestriction(DISALLOW_CROSS_PROFILE_COPY_PASTE)` | user-mediated |
| **File sharing** | cross-profile `ACTION_SEND` intent filter **+** per-item `content://` URI grants via `FileProvider` | **no filter, no grants** | install `ACTION_SEND` filter in the granted direction; each share is a **single foreground item** with a scoped URI grant | user-mediated |
| **Contacts search / caller-ID** | `setManagedProfileContactsAccessPolicy` / `setManagedProfileCallerIdAccessPolicy` (API 34+); legacy `setCrossProfileContactsSearchDisabled(true)` / `setCrossProfileCallerIdDisabled(true)` | **disabled / empty policy** | requires a **separate, stronger** consent; still discouraged (standing, background read) | **standing / ambient** |
| **Calendar** | `setCrossProfileCalendarPackages(admin, Set<String>)` (API 30+) | **empty allowlist** (none) | allowlist **exactly one named package**; note it is standing access | **standing / ambient** |
| **Connected apps / cross-profile widgets** | `setCrossProfilePackages(admin, Set<String>)` + `CrossProfileApps` | **none** | allowlist **exactly one named package**; flagged as **non-interactive standing link** | **standing / ambient** |
| **Notifications across profile** | framework default (work-badge notifications) | framework default | **not a Porog-managed crossing** — left to framework, not opened/closed here | out of scope |
| **Inbound share into managed profile** | `DISALLOW_SHARE_INTO_MANAGED_PROFILE` (parent restriction, where available) | may be **set** to block inbound | cleared only when a `p2w` file/intent crossing is granted | direction control |

> **API-level honesty:** the contacts/caller-ID surface was reworked across API
> levels (the `PackagePolicy`-based `setManagedProfile*AccessPolicy` methods are
> API 34+; the boolean `setCrossProfile*Disabled` methods are older and now
> deprecated). The reconcile loop MUST branch on `Build.VERSION.SDK_INT` and
> **fail closed** (apply the most restrictive available call) on any level where
> the intended API is absent. OEM behaviour varies; **only a real-device matrix
> settles the actual effect** (§6).

### 2.1 The rule for "safe to expose" vs "keep closed"

- **Exposable behind consent — user-mediated, foreground, per-item:**
  cross-profile `ACTION_SEND` (files/share) and clipboard. The user initiates each
  crossing; nothing moves in the background; Android itself surfaces a
  cross-profile warning on paste/share.
- **Keep hard-closed by default — standing / ambient / bulk:** cross-profile
  contacts search, caller-ID, calendar allowlisting, and `CrossProfileApps`
  connected-apps links. These grant **non-interactive, standing** access that
  reads without a per-use gesture. They require a **second, stronger** consent,
  default to hard-deny, and are labelled as standing access in the UI.
- **Never a blanket / bundled grant.** No "open everything" path exists. Each
  crossing opens **exactly one** capability in **exactly one** direction —
  anti-round-up, mirroring `noporis-gate`'s `openCrossing()` (opens one lever, and
  only while the bridge is standing).

---

## 3. The consent-gate contract

### 3.1 State-file contract (the single source of truth)

Porog consumes the **NoporIS gate state** as its input contract (NoporIS owns the
consent surface that *writes* it; Porog *reads and enforces* it). Porog extends
the shared crossing vocabulary with the DPM-specific crossings above; the extra
keys (`intents`, `contacts`, `calendar`, `connectedApp`) and a per-crossing
`direction` field must be coordinated into the shared schema with A4/A5 so there
is **one** state file, not a fork.

| Property | Value |
|---|---|
| **Canonical path** | DPC app-private storage inside the **managed profile's FBE-encrypted** dir: `files/porog-gate/state.json` (under the DPC package's private data dir). Documented, not world-anything. |
| **Ownership / mode** | Owned by the DPC app UID, `0600`-equivalent (app-private; not exported, not on a shared volume, not behind a world-readable ContentProvider). Never leaves the device; not telemetry. |
| **Format** | JSON. Discriminator `schema: "postern.porog-gate.state"`, `version: 1`. Refuse a foreign/unknown `schema` or `version` outright → full-deny. |
| **Writer** | the **consent UI** (user-driven code path). It is the *only* path that sets `consent.accepted` or opens a crossing. |
| **Reader** | the **DPC policy-application code path** (the reconcile loop). It **never writes** grant state; it only reads and reconciles framework policy to match. |

**Reader/writer split.** Even when the consent UI and the DPC live in one app,
the split is enforced by construction, exactly as the Waydroid wrapper is a pure
*reader* of a state file owned by a separate consent-gate component: the
policy-apply code path treats the file as **read-only input** and never mutates
grants; only the user-driven consent Activity writes. Kill-switch engage is the
one write the reconcile side may perform on itself (§3.4), and it only ever moves
toward *more* closed.

### 3.2 State shape (v1)

```jsonc
{
  "schema": "postern.porog-gate.state",   // discriminator; foreign file → full-deny
  "version": 1,                           // unknown version → full-deny
  "tier": "key-attested-device",          // PINNED. attests the phone, NOT the
                                          // workspace. Never read from input; no
                                          // code path can relabel it "measured-boot".
  "consent": {
    "accepted": false,                    // DEFAULT DENY. true only after honest disclosure read + accepted
    "scope": "session",                   // "session" (re-ask next boot) | "persistent"; safer default = session
    "acceptedAtIso": null
  },
  "crossings": {
    // user-mediated, per-item — exposable behind consent
    "intents":   { "open": false, "direction": "none", "scope": "session", "openedAtIso": null },
    "clipboard": { "open": false, "direction": "none", "scope": "session", "openedAtIso": null },
    "files":     { "open": false, "direction": "none", "scope": "session", "openedAtIso": null },
    // standing/ambient — hard-deny, require a SEPARATE stronger consent
    "contacts":     { "open": false, "direction": "none", "scope": "session", "openedAtIso": null },
    "calendar":     { "open": false, "direction": "none", "scope": "session", "openedAtIso": null, "package": null },
    "connectedApp": { "open": false, "direction": "none", "scope": "session", "openedAtIso": null, "package": null }
  },
  "killSwitch": {
    "engaged": false,                     // true = door slammed; nothing crosses; refuse to open until disengaged
    "engagedAtIso": null
  },
  "sealedWallet": {
    "preserved": true                     // PINNED true. No input, no kill-switch path can clear it.
  }
}
```

**Field semantics (the honesty rails, enforced in code, not just prose):**

1. **`tier` is pinned `"key-attested-device"`** — set by `defaultState()`, never
   read from input. It means *the phone is key-attested; the workspace is not
   measured-boot*. No path can silently upgrade the phrasing to "attested
   workspace."
2. **Every crossing DEFAULTS TO DENY (`open:false`, `direction:"none"`).** Any
   value that is not exactly `true` — missing, garbage, `"true"` string, truthy
   non-`true` — collapses to closed. `direction` that is not one of
   `"p2w" | "w2p" | "both"` collapses to `"none"`.
3. **Anti-round-up.** Opening a crossing opens **exactly one** capability in
   **exactly one** direction, **only** while the bridge is standing
   (`consent.accepted && !killSwitch.engaged`); otherwise it is a no-op.
4. **Fail-closed.** A missing/unparseable/partial file, an unknown `schema`/
   `version`, or any missing field normalises to **full-deny + not-consented**.
   A corrupt file can never open a crossing.
5. **The kill-switch drops the span but NEVER destroys the sealed wallet.**
   `sealedWallet.preserved` is pinned true, like `tier`; no input path clears it.
6. **Revocation collapses to "never given."** A revoked/expired crossing is
   byte-indistinguishable from one that was never opened.

### 3.3 How the DPC reads and enforces — the reconcile loop

The DPC runs an **idempotent reconcile** that makes the live DPM policy match the
gate state. It is the enforcement heart of A3.

**Triggers:** `ACTION_PROFILE_PROVISIONING_COMPLETE`, boot-completed (within the
profile), and a change signal when the consent UI writes the state file (a
`FileObserver` on `files/porog-gate/` or an explicit intent from the consent
Activity). Also runs on `disengage` of the kill-switch.

**Algorithm (fail-closed):**

```
state = normalize(readOrNull("files/porog-gate/state.json"))   // never throws; null → defaultState()
if !state.consent.accepted || state.killSwitch.engaged:
    applyFullDeny()                                            // see §3.4
    return
for each crossing c in state.crossings:
    if c.open == true (exactly) and c.direction ∈ {p2w,w2p,both}:
        installGrant(c)      // narrow filter / clear the one restriction / allowlist one package
    else:
        removeGrant(c)       // clear that filter / re-impose the restriction / empty the allowlist
audit.append(transition)     // §3.5
```

`installGrant`/`removeGrant` map one crossing to exactly the calls in the §2
table, honouring `direction` via the intent-filter flags. Reconcile is
**idempotent** and **convergent**: running it twice is a no-op; running it after a
crash re-derives policy purely from state. It **only ever installs the narrow
grants the state names** and clears everything else — there is no additive drift.

### 3.4 The kill-switch (`applyFullDeny`)

`killSwitch.engaged = true` (or any not-consented / fail-closed path) makes the
DPC:

1. `clearCrossProfileIntentFilters(admin)` — remove **all** cross-profile intent
   filters (both directions).
2. `addUserRestriction(admin, DISALLOW_CROSS_PROFILE_COPY_PASTE)` — re-block
   clipboard.
3. Set contacts/caller-ID to the most restrictive available policy; empty the
   `setCrossProfileCalendarPackages` and `setCrossProfilePackages` allowlists.
4. `revokeUriPermission(...)` for outstanding `content://` grants the DPC issued;
   set `DISALLOW_SHARE_INTO_MANAGED_PROFILE` where available.
5. **Refuse to install any crossing** until `engaged` returns to `false`.
6. **Never** wipe/alter the sealed wallet or keys (`sealedWallet.preserved`).

**Honesty bound on the kill-switch:** it closes the door for **future** flows and
revokes **live** grants — it **cannot retract bytes already copied** across the
boundary. Content-URI grants already consumed, or data already pasted, are gone
from the DPC's reach. The UI must say so.

A fast path (a quick-settings tile / notification action) flips
`killSwitch.engaged = true` and triggers reconcile — the one self-write the
enforcement side may perform, and it only moves toward *more closed*.

### 3.5 Audit trail (local, non-telemetry)

The DPC appends to a local, managed-profile-private, append-only log every policy
**transition**: timestamp, which crossings changed, resulting direction, and the
trigger (provisioning / boot / state-change / kill-switch). This never leaves the
device and is not telemetry.

**What the audit can and cannot see (honest bound):** the DPC logs *that it
installed/cleared a cross-profile `ACTION_SEND` filter or a restriction* — i.e.
**policy transitions**. It does **not** and cannot log each individual file the
user then shares or each clipboard paste; those are mediated by the framework
after the grant, below the DPC's visibility. The audit proves *what the boundary
was configured to allow, and when* — not a byte-level record of what crossed.

---

## 4. Data-flow model — private persona ⟷ Google-Play persona

| Crossing | May cross? | Direction(s) | Under what consent | Audit |
|---|---|---|---|---|
| **Default (no grant)** | **Nothing** | — | — | partition logged at provision/boot |
| **`files` (share sheet)** | single foreground item, user-initiated | `p2w` and/or `w2p`, each granted separately | primary consent + per-crossing open | filter install/clear logged |
| **`clipboard`** | user-initiated copy/paste | `p2w` and/or `w2p` | primary consent + per-crossing open | restriction toggle logged |
| **`intents` (app launch)** | narrow action only | granted direction | primary consent + per-crossing open | filter install/clear logged |
| **`contacts` / caller-ID** | standing read | direction as granted | **separate stronger** consent; default hard-deny | policy change logged |
| **`calendar`** | standing read, one named package | direction as granted | **separate stronger** consent; named package | allowlist change logged |
| **`connectedApp`** | standing non-interactive link, one named package | direction as granted | **separate stronger** consent; named package | allowlist change logged |

**Direction defaults when a crossing *is* opened.** The consent UI SHOULD default
a freshly-opened file/intent crossing to the **less-leaky** direction and require
a second gesture to add the `p2w` (into-Google) direction, because `p2w` moves
private data to the side that phones home. Porog enforces whatever the state says;
this is a *UI default* recommendation to A4/A5, and Porog's honest labelling must
name the Google side as less-private in both directions.

**This is the surface NoporIS drives.** NoporIS writes `consent`/`crossings`/
`killSwitch`; Porog's reconcile is the enforcement side. Both sides run the **same
fail-closed normalise + `bridgeStanding` predicate** (`consent.accepted &&
!killSwitch.engaged`), exactly as `porog-tor-glue` and `sloboda-gate`
share one `egressAllowed`/`egress_decision` rule. Keep the predicate in **one**
tested kernel that both import.

---

## 5. Files & components

| Path (proposed) | Role | Owner |
|---|---|---|
| `apps/noporis-gate/gate-store.mjs` *(extend)* | shared consent kernel: `normalize` / `bridgeStanding` / `openCrossing` + the new `direction` field and DPM-crossing keys. **One** source of truth NoporIS writes and Porog reads. | A4/A5 + A3 (schema coordination) |
| `apps/noporis-gate/gate-state.schema.json` *(extend)* | draft-07 schema: add `direction`, `intents`/`contacts`/`calendar`/`connectedApp`, pinned Porog `tier`. | A4/A5 + A3 |
| `apps/porog-crossprofile/reconcile-kernel.mjs` *(new, host-testable)* | **pure** decision kernel: given normalized state → the exact list of DPM grants to install/clear (no Android imports). The macOS-host-runnable proof of the fail-closed + anti-round-up + kill-switch logic. | A3 |
| `apps/porog-crossprofile/test-reconcile.mjs` *(new)* | `node test-reconcile.mjs` — asserts default-deny, unknown-version → full-deny, corrupt → full-deny, anti-round-up, kill-switch clears all, direction flags correct. | A3 |
| Kotlin DPC: `PorogDeviceAdminReceiver` + profile-owner provisioning | `ACTION_PROVISION_MANAGED_PROFILE`, becomes profile owner. **Owned by the Kotlin/DPC dev tree** (not authored in A3; A3 specifies the cross-profile policy it must apply). | DPC dev / A3 spec |
| Kotlin: `CrossProfileReconciler` | reads `files/porog-gate/state.json`, runs §3.3 reconcile, maps crossings → the §2 DPM calls, writes the audit log. **A3's enforcement contract, realised in the DPC tree.** | DPC dev / A3 spec |
| Kotlin: consent UI Activity | the **only** writer of grant state; renders honest disclosure (Google side less-private; standing vs user-mediated; can't un-send). | A4/A5 (NoporIS surface) |
| `docs/design/porog-03-crossprofile-bridge.md` | **this document.** | A3 |

Not owned here: the DPC/Kotlin internals, `postern-sdk` FFI, and the StrongBox
attestation verifier (Dev-C). A3 owns the **cross-profile policy contract** and
the **host-testable reconcile kernel**; the Kotlin realisation consumes it.

---

## 6. Build / test — toolchain, infra, and the functional proof

**Reality: the macOS host has NO Android SDK.** A Linux+Nix VM is coming.

### 6.1 What runs on the macOS host **now** (no Android)

The reconcile *logic* is pure and provable with `node`, exactly as the existing
`*-gate` kernels are node-tested:

- `node apps/porog-crossprofile/test-reconcile.mjs` — proves default-deny,
  fail-closed (missing / corrupt / unknown-version / partial → full-deny),
  anti-round-up (one lever ⇒ one grant, and only while standing), kill-switch
  clears everything, and that each `direction` maps to the correct intent-filter
  flag set.
- JSON-schema validation of `state.example.json` against the extended schema.

This proves the **policy decision** is correct. It proves **nothing** about
whether the DPM calls behave on a device.

### 6.2 What the Linux+Nix VM + a work-profile **emulator** can prove

Nix provisions `android-sdk` (cmdline-tools, platform-tools, emulator, a system
image). Run a headless AVD, provision a managed profile with the Porog DPC (or
`TestDPC` standing in for the profile owner while the Kotlin DPC is stubbed), and
drive it with `adb` / `dpm` / `am`:

**CAN prove (emulator is sufficient):**

1. Self-enrolled provisioning via `ACTION_PROVISION_MANAGED_PROFILE` succeeds and
   the DPC becomes profile owner.
2. `addCrossProfileIntentFilter` / `clearCrossProfileIntentFilters` actually gate
   `startActivity` across the boundary — and the **direction flags** are honoured.
3. `DISALLOW_CROSS_PROFILE_COPY_PASTE` actually blocks paste across profiles.
4. `setCrossProfileCalendarPackages` / contacts / caller-ID policies apply at the
   claimed API level (and the `SDK_INT` branch falls back closed on older levels).
5. The reconcile loop is idempotent and convergent; kill-switch clears all
   filters + re-imposes restrictions; a corrupted state file drives full-deny.

**CANNOT prove (needs a real device — honesty rail):**

- **StrongBox key-attestation.** The emulator has no hardware TEE/StrongBox;
  attestation returns software-backed or fails. The **"key-attested device"**
  claim is only settled on real hardware (Dev-C).
- **OEM cross-profile behaviour variance** across vendors/skins/Android versions.
- **Play Integrity reality** on the Google-Play persona and which apps refuse.
- That the on-device consent-UI writer and the DPC reader agree on the real
  state-file path/format under the profile's FBE storage (mirrors the Waydroid
  README's open item #13).

### 6.3 The functional-proof test (scripted emulator scenario)

**Where:** the Linux+Nix VM, headless AVD + `adb`. (The pure kernel test in §6.1
runs anywhere, including the macOS host.)

```
1. Provision managed profile with the DPC (or TestDPC). Assert profile owner set.
2. BASELINE: attempt cross-profile share (ACTION_SEND) and cross-profile paste.
   → both BLOCKED (no filter; copy-paste restricted). Assert.
3. Write state: crossings.files = { open:true, direction:"w2p" }; signal reconcile.
   → ACTION_SEND resolves managed→personal ONLY; personal→managed still blocked;
     clipboard still blocked. Assert each.
4. Write state: crossings.clipboard = { open:true, direction:"both" }; reconcile.
   → cross-profile paste now works both ways. Assert.
5. Flip killSwitch.engaged = true; reconcile.
   → all cross-profile filters cleared; copy-paste restricted again; share blocked.
     Assert. Assert sealed-wallet-preserved invariant untouched.
6. Corrupt state.json (truncate); reconcile.
   → DPC applies full-deny (fail-closed). Assert baseline restored.
```

Passing steps 2–6 is the functional proof that Porog's cross-profile enforcement
matches the consent state and is default-safe. Step 1's *attestation* claim is
explicitly out of the emulator's reach and is deferred to §6.2's real-device item.

---

## 7. Phased dev task-list

| Phase | Where | Work | Devs |
|---|---|---|---|
| **P0 — kernel (now, host)** | macOS host, `node` | Extend the shared gate schema/kernel with `direction` + DPM-crossing keys; write `reconcile-kernel.mjs` + `test-reconcile.mjs`; prove default-deny / fail-closed / anti-round-up / kill-switch **without Android**. | 1 (A3), coordinate schema with A4/A5 |
| **P1 — DPC skeleton (VM)** | Linux+Nix VM | Nix `android-sdk`; profile-owner provisioning (`ACTION_PROVISION_MANAGED_PROFILE`); `CrossProfileReconciler` wired to read `files/porog-gate/state.json` and call the kernel. | 1–2 (A3 spec + DPC dev) |
| **P2 — enforcement mapping (VM emulator)** | headless AVD | Realise the §2 table: intent-filter install/clear with direction flags, `DISALLOW_CROSS_PROFILE_COPY_PASTE`, calendar/contacts/caller-ID with `SDK_INT` fallbacks; the §6.3 functional-proof scenario green. | 1 (A3) |
| **P3 — kill-switch, audit, consent UI (VM)** | VM + emulator | Fast-path kill-switch tile → reconcile; append-only audit log; consent-UI writer (NoporIS surface) with honest labelling (less-private Google side, standing vs user-mediated, can't-un-send). | 1 (A3 + A4/A5 for UI) |
| **P4 — real device (hardware)** | real phone w/ StrongBox | StrongBox key-attestation binding + honest label verification; OEM/Android-version cross-profile behaviour matrix; confirm on-device state-file path/format agreement. | 1 (overlaps Dev-C attestation) |

**Dev count:** ~**3–4 engineers** across phases, with real overlap — A3 owns the
policy contract + host kernel + enforcement mapping; A4/A5 own the NoporIS consent
surface that writes the shared state; the Kotlin/DPC dev realises the reconciler;
Dev-C owns the P4 attestation binding. P0 is unblocked today on the macOS host;
P1–P3 need the Linux+Nix VM; P4 needs real hardware.

---

## 8. Honesty / default-safe constraints (checklist — must hold in any shipped surface)

- [x] **Default-SAFE:** bridge CLOSED unless an explicit consent state says
      otherwise; anything but exactly `true` (per crossing) / a valid consented
      state = off. Fail-closed on missing/corrupt/unknown-version.
- [x] **Porog attests the phone, not the workspace** — `tier` pinned
      `"key-attested-device"`; never relabelled "measured-boot workspace."
- [x] **Stock, un-rooted Android, self-enrolled DPC**; never "Postern OS."
- [x] **A rooted/compromised host defeats the boundary**; userland framework
      policy, not a kernel/measured boundary.
- [x] **The Google-Play side is the less-private side, in both directions**;
      NoporIS sells separation, not privacy — Porog enforces the partition, it
      does not make the Google side private.
- [x] **Kill-switch drops the span, never destroys the sealed wallet**
      (`sealedWallet.preserved` pinned); and it **cannot un-send** bytes already
      crossed.
- [x] **DPC governs only the profile it owns**; it cannot police the personal
      side after data crosses.
- [x] **Respect Google/Android licenses** — no GMS redistribution, no
      Play-Integrity/SafetyNet circumvention, nominative naming only.
- [x] **Standing/ambient crossings (contacts/calendar/connected-apps) hard-deny by
      default**, require a separate stronger consent, and are labelled as standing
      access.
- [x] **Audit is local, non-telemetry**, and honestly bounded to policy
      transitions (not byte-level records of what crossed).
- [x] **UNAUDITED reference-prototype**; the coin is worthless / not a security;
      personal use is free; **not legal advice**. Porog / NoporIS names pending
      trademark clearance.

---

## 9. Top risks

1. **API-level & OEM variance** in the cross-profile surface (contacts/caller-ID
   reworked at API 34; `DISALLOW_SHARE_INTO_MANAGED_PROFILE` availability; skin
   behaviour). Mitigation: `SDK_INT` branching that **fails closed**, plus the P4
   real-device matrix. Emulator cannot settle this.
2. **Data already crossed is unrecoverable.** The kill-switch/revocation cannot
   retract copied bytes or consumed URI grants. Mitigation: honest UI labelling;
   default file/intent crossings to the less-leaky direction; keep grants narrow
   and per-item.
3. **Reader/writer split integrity.** If any policy-apply path ever writes grant
   state, default-safe is broken. Mitigation: keep the reconcile side a pure
   reader (its only self-write is kill-switch-toward-closed); enforce in the
   host-testable kernel.
4. **Schema fork between NoporIS and Porog.** Two divergent state files would
   desync consent from enforcement. Mitigation: one shared kernel/schema; the
   same `normalize` + `bridgeStanding` predicate on both sides (the
   `porog-tor-glue`/`gate` precedent).
5. **Attestation over-claim.** Presenting a StrongBox device key as an "attested
   workspace." Mitigation: `tier` pinned to `"key-attested-device"`; standing
   honesty header; P4 label verification on hardware.
6. **Standing crossings normalised as routine.** Contacts/calendar/connected-apps
   are ambient leaks if treated like the user-mediated ones. Mitigation: separate
   stronger consent, hard-deny default, explicit "standing access" labelling.

---

*Design and scaffold only; UNAUDITED. Do not treat any file described here as a
security control. Porog and NoporIS are proposed names, pending trademark
clearance. Never "Postern OS."*
