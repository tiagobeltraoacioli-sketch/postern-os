<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Porog Cross-Profile Gate — the guarded door's decision core

**Status: DESIGN / reference-prototype. UNAUDITED — certifies nothing about security.**

The deny-by-default reconcile kernel for **Porog** (Slavic: threshold / soleira — the
door between two worlds), the guarded **door** built on the stock-Android
managed-profile container: one work (managed) profile and one personal profile on the
same handset. This directory models **only the decision core** — the pure function that
turns shared consent state into the exact set of cross-profile intent-filter directives
a Device Policy Controller (DPC) would apply. It does **not** apply anything on a device.

> ## ⚠ HONESTY HEADER — read before trusting anything here
>
> - **`tier` is always `"key-attested-device"`, pinned, never taken from input.**
>   Porog attests the **phone** — a key-attested Android device — **not the workspace**.
>   That is **not** a measured-boot workspace and it is **never a Postern Seal**. No
>   file, no code path, can relabel it as workspace-attested or Seal-covered.
> - **Default-deny, fail-closed, at every step.** Every crossing defaults to
>   `direction: "none"`. An unrecognised or mismatched `schema`/`version`, a malformed
>   blob, or an unparseable state file all collapse to **FULL-DENY** — `defaultState()`
>   in full. A foreign-schema blob is **never re-stamped or cherry-picked**: normalising
>   it would be schema laundering (a wrong-schema blob with `consent.accepted:true`
>   surviving as a recognised, possibly-open state), so nothing from it survives.
> - **Direction is first-class and never rounds up.** `none` / `p2w` / `w2p` / `both`
>   map to explicit `FLAG_PARENT_CAN_ACCESS_MANAGED` / `FLAG_MANAGED_CAN_ACCESS_PARENT`
>   DPC flags — never a silent grant, never both flags unless `both` was stored exactly.
>   The clipboard crossing is the one exception worth naming: `DISALLOW_CROSS_PROFILE_COPY_PASTE`
>   is **directionless at the OS level** — any non-`none` clipboard direction lifts
>   copy/paste in **both** directions regardless of the stored value — so
>   `clipboard.direction` is **advisory** (a record of user intent), not an
>   OS-enforced direction.
> - **Standing/ambient caps are hard-deny by construction.** `contacts`, `calendar`,
>   and `connectedApp` grant background, un-mediated access once open, so each additionally
>   requires the **stronger** `consent.standing` on top of base `consent.accepted` and a
>   non-`none` direction. Without it they stay denied no matter what direction is stored.
> - **Kill-switch clears everything.** Engaging `killSwitch.engaged` clears **all**
>   directives, empties every allowlist, and re-imposes `DISALLOW_CROSS_PROFILE_COPY_PASTE`
>   — regardless of any crossing's stored direction or consent state.
>   `sealedWallet.preserved` is pinned `true`, exactly like `tier`; no input and no
>   kill-switch path can unpin it.
> - **THE HONEST BOUND.** This kernel governs **only** the DPC-owned managed (work)
>   profile. It has **no authority over the personal profile**. And it cannot un-send
>   bytes: closing a crossing stops **future** crossings — it does **not** recall bytes
>   that have **already crossed**.
> - **The Kotlin DPC that APPLIES these directives is scaffold, compile-correct by
>   inspection only, and UNTESTED on any device.** This kernel stays the ONE decision
>   authority; its single Kotlin port
>   (`android-container/.../dpc/CrossProfileReconciler.decide()`) is pinned to it by the
>   committed `golden-vectors.json` (from `export-vectors.mjs`) and a plain-JVM parity
>   test, so the two can never silently drift. But `addCrossProfileIntentFilter`,
>   `setCrossProfilePackages`, and the `DISALLOW_CROSS_PROFILE_COPY_PASTE` user
>   restriction — the actual enforcement — have **never been compiled against an Android
>   SDK here, never run on a device**, and prove nothing until the VM/T1/device work runs.
> - **UNAUDITED reference-prototype.** No on-device enforcement, no DPC, no audit, and
>   no security guarantee exist yet. The coin is worthless and is **not a security**.
>   Personal use is free. **This is not legal advice.**

## What this is (and is not)

- **Door, not bridge.** Porog (`apps/izbushka` + the stock-Android managed-profile
  container) is the guarded **door**; **NoporIS** (`apps/noporis-gate`) is the guarded
  **bridge**. Two products, two folklore shapes, one shared consent-kernel pattern. This
  directory models **only the door's cross-profile decision core** — which capabilities
  cross between the work and personal profile, in which direction, and the kill-switch.
- **A decision kernel, not the enforcement.** `reconcile-kernel.mjs` is the canonical,
  node-tested source of truth for the directive set a DPC would install. It computes
  intent-filter flags, cross-profile package allowlists, and the copy/paste restriction
  state from a consent blob — and nothing more. It does not touch a device, a profile,
  or Android at all.
- **Mirrors the house pattern.** Same deny-by-default / fail-closed / pinned-honesty-rail
  shape as `apps/sloboda-gate/gate-store.mjs` and `apps/noporis-gate/gate-store.mjs`, and
  the same fail-closed egress seam style as `apps/porog-tor-glue`'s `egress_decision` ↔
  `apps/noporis-gate`'s `egressAllowed`. Those directories are **not** modified here.

## Files

| File | Role |
|---|---|
| `reconcile-kernel.mjs` | Canonical DOM-free, dependency-free decision core: `normalize` (trust boundary) + `reconcile` (state → DPC directives) + pure helpers. No network, no telemetry, no imports. |
| `gate-state.schema.json` | JSON Schema (draft-07) for the persisted consent state file. |
| `state.example.json` | A fresh, fully-safe state (not consented, every crossing `"none"`, kill-switch clear, wallet preserved). |
| `test-reconcile.mjs` | `node test-reconcile.mjs` — asserts the honesty rails hold in code (321 checks). |
| `export-vectors.mjs` | `node export-vectors.mjs` — deterministically replays a full input matrix through `reconcile()` and (re)writes `golden-vectors.json`. Regenerate in the SAME commit as any kernel change. |
| `golden-vectors.json` | The COMMITTED golden vectors pinning the single Kotlin port (`labs.postern.container.dpc.CrossProfileReconciler.decide()`) to this kernel, field by field, via the plain-JVM `CrossProfileReconcilerParityTest` in `android-container/profile` — the anti-drift rail between the two implementations of the one decision. |

## The honesty rails, enforced in code (not just prose)

1. **`tier` is always `"key-attested-device"`** — pinned by `defaultState()`, never read
   from input. Porog attests the **phone**, never the workspace, and never a Postern
   Seal; no file can relabel it.
2. **Default-deny + fail-closed.** Every crossing's `direction` defaults to `"none"`.
   `schemaRecognized()` demands an *exact* match on `schema` and `version`; anything
   else — missing, wrong id, wrong/stringified version, unparseable JSON — drives
   `closedDirectives()`: no intent filters, no cross-profile package allowlist, copy/paste
   disallowed. A recognised-but-malformed blob normalises through `normalize()` to the
   same safe defaults field-by-field; it can never partially open.
3. **No schema laundering.** A blob that fails `schemaRecognized()` is a **foreign**
   blob, not ours to interpret. It is never re-stamped with our pinned `schema`/`version`
   and cherry-picked for fields — `reconcile()` and `normalize()` both return
   `defaultState()` in full, with nothing from the foreign blob surviving.
4. **Direction is first-class and never rounds up.** `DIRECTION_FLAGS` maps `none` / `p2w`
   / `w2p` / `both` to the *exact* `FLAG_PARENT_CAN_ACCESS_MANAGED` /
   `FLAG_MANAGED_CAN_ACCESS_PARENT` combination — a garbage or partial direction
   normalises to `"none"` and installs nothing. `DISALLOW_CROSS_PROFILE_COPY_PASTE` is
   the one directionless mechanism at the OS level: any non-`"none"` clipboard direction
   lifts it in **both** directions, so `clipboardDirection` is carried through as advisory
   record, not an enforced direction.
5. **Standing/ambient caps are hard-deny.** `contacts`, `calendar`, and `connectedApp`
   are `CAP_CLASS: "standing"`; `reconcile()` additionally requires
   `s.consent.standing === true` before installing their `crossProfilePackages` entry,
   on top of base `consent.accepted` and a non-`"none"` direction. User-mediated caps
   (`intents`, `files`, `clipboard`) need only base consent.
6. **Kill-switch clears ALL directives.** `killSwitch.engaged` short-circuits `reconcile()`
   to `closedDirectives(..., { cleared: true })`: empty intent filters, empty allowlist,
   `copyPasteDisallowed: true`, `clipboardDirection: "none"` — regardless of any stored
   crossing or consent. `sealedWallet.preserved` is pinned `true` exactly like `tier`;
   no state file and no kill-switch path can unpin it.
7. **The honest bound is carried on every decision.** `CAVEATS` — governs only the
   DPC-owned managed profile, no authority over the personal profile, cannot un-send
   bytes already crossed, clipboard directionlessness, UNAUDITED/no-security-guarantee —
   ships on every `reconcile()` output (`open: true` or `false`), not just in this
   README.

## API surface

```
defaultState()                 -> fully-safe state (what to assume when the file is absent)
schemaRecognized(input)        -> is this EXACTLY our schema id + version? (guards against laundering)
normalize(input)               -> valid state, never throws (the trust boundary)
parse(text) / serialize(state) -> JSON <-> normalized state (parse never throws)

reconcile(input)      -> the DPC directive set: intentFilters, crossProfilePackages,
                          copyPasteDisallowed, clipboardDirection, sealedWalletPreserved,
                          caveats (fail-closed at every step, see CAVEATS)
reconcileText(text)   -> reconcile() straight from on-disk JSON text; parse failure => full-deny
crossingOpen(state, cap) -> is this one capability open right now? (mirrors reconcile exactly)
```

All functions are pure, clock-free (timestamps are caller-supplied), and free of
network/telemetry/imports.

## Rails checklist (must hold in any Porog surface that ships)

- [x] `tier` pinned `"key-attested-device"` — phone-attested, never workspace-attested,
      never a Postern Seal.
- [x] Every crossing **defaults to `direction: "none"`**; nothing opens without explicit,
      recognised consent.
- [x] Unknown/mismatched `schema`/`version`, malformed blob, or unparseable file all
      **FULL-DENY** — no partial opens, no schema laundering.
- [x] Direction is explicit and **never rounds up**; clipboard's OS-level
      directionlessness is disclosed, not hidden.
- [x] Standing/ambient caps (`contacts`, `calendar`, `connectedApp`) hard-deny without
      the **stronger** `consent.standing`.
- [x] Kill-switch clears **all** directives and re-imposes
      `DISALLOW_CROSS_PROFILE_COPY_PASTE`; `sealedWallet.preserved` pinned `true`.
- [x] States THE HONEST BOUND: managed-profile-only authority, cannot recall bytes
      already crossed.
- [x] Never claims more of the Kotlin DPC than is true: it exists as **scaffold,
      compile-correct by inspection only** — pinned to this kernel by the committed
      golden vectors + JVM parity test — but it has **never run on a device** and no
      audit exists; enforcement is unproven until the VM/T1/device work runs.
- [x] Carries the standing disclaimers: **UNAUDITED / reference-prototype**, **coin
      worthless / not a security**, **personal-free**, **not legal advice**.

---

*Design and scaffold only; UNAUDITED. No on-device enforcement exists. Do not treat any
file here as a security control.*
