<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# NoporIS Gate — the guarded crossing

**Status: DESIGN / reference-prototype. UNAUDITED — certifies nothing about security.**

The deny-by-default consent kernel for **NoporIS, the guarded *bridge*** (the Kalinov
crossing): a *controlled* passage between two personas on one stock handset — a near/clean
side and a far Google-Play side — that both keep existing. This models the crossing as a
**deliberate, per-capability hand-over**: each capability that crosses is a lever the user
throws, off by default and individually revocable, plus a bridge **kill-switch** that
drops the span **without ever destroying sealed wallet state** on the near side.

> ## ⚠ HONESTY HEADER — read before trusting anything here
>
> - **The Google-Play side is the LESS-PRIVATE side, by construction.** That persona runs
>   Google Play Services and **phones home to Google**. NoporIS sells **separation +
>   convenience, not privacy on that side.** It cannot make a Google-Android persona private.
> - **NoporIS is an app on stock Android. It is NEVER "Postern OS".** It does not own the
>   kernel, bootloader, baseband, or TEE. Its isolation is **Android's own** work-profile
>   mechanism, configured by an unprivileged app — only as strong as the kernel underneath.
> - **`tier` is always `non-attestable`.** No Seal, no measured boot; nothing here can
>   relabel it as attested. (Unlike the Waydroid community edition, there is **no Tor-only
>   egress rail** — the far side uses normal networking.)
> - **A rooted / unlocked / kernel-compromised host defeats the separation.** Sandboxed is
>   **not** secure, private, or attested.
> - **UNAUDITED reference-prototype.** The on-device wrapper that consumes this state does
>   not exist yet (UNTESTED). The coin is worthless and is **not a security**. Personal use
>   is free. **This is not legal advice.**
> - **"Nopor" is a coined mark**, not folklore; **NoporIS/Nopor needs formal trademark
>   clearance** before the mark is committed (shares the existing "NOPOR" filing root).

## What this is (and is not)

- **Bridge, not door.** NoporIS is the guarded **bridge**; **Porog** (`apps/izbushka` +
  the stock-Android managed-profile container) is the guarded **door**. Two products, two
  folklore shapes, one shared signer core. This directory models **only the bridge's
  consent gate** — which capabilities are lent across, and the kill-switch.
- **A reference kernel, not the wrapper.** `gate-store.mjs` is the canonical, node-tested
  source of truth for the state shape the on-device wrapper would read. The wrapper does
  not exist. `index.html` is a self-contained demo that inlines a condensed,
  behavior-equivalent port (it omits `parse`/`loadState`/`serialize`/`revokeAllCrossings`, which
  the demo does not need); the `.mjs` is canonical and node-tested, and the copy is
  kept in sync manually, not generated.
- **Reuses the deny-by-default kernel pattern** from `apps/sloboda-gate`
  (deny-by-default per-capability toggles + kill-switch + `normalize()` trust boundary),
  adapted to the crossing model. That directory is **not** modified.

## Files

| File | Role |
|---|---|
| `gate-store.mjs` | Canonical DOM-free, dependency-free consent kernel (normalize + decision helpers + pure state transformers). |
| `gate-state.schema.json` | JSON Schema (draft-07) for the persisted state file. |
| `state.example.json` | A fresh, fully-safe state (not consented, every crossing denied, wallet preserved). |
| `test-store.mjs` | `node test-store.mjs` — asserts the honesty rails hold in code (82 checks, incl. the `loadState()` strict on-disk boundary: foreign-schema / unknown-version / missing-discriminator rejection, and the schema/example conformance pair). |
| `index.html` | Self-contained honest UI: honesty strip, consent gate, crossing levers, kill-switch, wallet-preserved assertion. No network, no telemetry. |

## The honesty rails, enforced in code (not just prose)

1. **`tier` is always `"non-attestable"`** — pinned by `defaultState()`, never read from
   input. No file can relabel the far side as attested.
2. **Every crossing DEFAULTS TO DENY (never given).** Missing/garbage/`truthy-but-not-true`
   input collapses to closed. A crossing is only ever open by an explicit, disclosed toggle.
3. **Anti-round-up — never a silent grant.** `openCrossing()` opens **exactly one**
   capability and **only** while the bridge is standing (consented + not killed); otherwise
   it is a no-op. Nothing bundles; nothing crosses that the user did not hand across.
4. **Fail-closed.** `activeCrossings()` returns `[]` whenever consent is missing or the
   kill-switch is engaged. A malformed or partial blob normalises to full-deny +
   not-consented — a corrupt file can never open a crossing.
5. **The kill-switch drops the span but NEVER destroys the sealed wallet.**
   `sealedWallet.preserved` is pinned true (like `tier`); no input and no kill-switch path
   can clear it. `walletPreserved()` is true by construction. The near side — the door, the
   keys — survives the span dropping.
6. **Revocation collapses to "never given."** `revokeCrossing()` /
   `revokeAllCrossings()` / `withdrawConsent()` return a state indistinguishable from one
   where the hand-over was never made.

## API surface

```
defaultState()                         -> fully-safe state (what to assume when the file is absent)
normalize(input)                       -> valid state, never throws (the trust boundary)
parse(text) / serialize(state)         -> JSON <-> normalized state (parse never throws; TOLERANT, no schema/version check)
loadState(text)                        -> STRICT on-disk boundary: foreign schema / unknown version / non-object => full-deny, before normalize

bridgeStanding(state, {requireConsent})-> may anything cross at all? (consent && !killSwitch)
activeCrossings(state)                 -> capabilities actually lent across right now (fail-closed)
walletPreserved(state)                 -> true by construction

slobodaBridgeToggle(state)             -> "enabled" iff standing && !killSwitch && a crossing is lent, else "disabled"
slobodaBridgeStateFile(state)          -> the derived sloboda-bridge.state body (line 1 = the toggle)

acceptConsent / withdrawConsent        -> enter / leave the bridge
openCrossing(state, key, {scope,direction}) -> throw ONE lever, one DIRECTION lane (no-op without consent)
revokeCrossing / revokeAllCrossings    -> collapse a crossing (or all) to never-given
engageKillSwitch / disengageKillSwitch -> drop / restore the span (wallet always preserved)
```

All transformers are pure (return a new normalized state), clock-free (timestamps are
caller-supplied), and free of network/telemetry/imports.

### Two consumer-facing keys (added for the wider fleet)

- **`crossings.{cap}.direction`** — the DPM (data-policy / crossing-direction) lane the
  cross-persona bridge glue (`apps/noporis-bridge-glue`) reads. A crossing authorises
  **exactly one** lane, never both: `near-to-far` (clean side hands a capability to the
  Google side) or `far-to-near` (the more-dangerous ingest lane — the Google side pushes
  INTO the hardened side, chosen on purpose). Missing/unknown collapses to `near-to-far`;
  optional in the schema so pre-direction files still validate. Mirrors the signed
  per-direction ConsentRecord (noporis-02 §2): clipboard near→far does **not** authorise
  clipboard far→near.
- **`slobodaBridgeToggle` / `sloboda-bridge.state`** — the tiny derived toggle file (canonical
  `/run/postern/consent/sloboda-bridge.state`, `SLOBODA_BRIDGE_PATH`) that Porog's
  cross-profile enforcement side and the Waydroid wrapper (`apps/sloboda`) read
  **read-only** (noporis-02 §3.2). NoporIS is the **sole writer**; the span is up only if
  line 1 is exactly `enabled`. Engaging the kill-switch projects `disabled` at once, so a
  polling consumer sees the span drop immediately. Write it atomically (temp + fsync +
  rename). Fail-closed: missing/garbage state projects `disabled`.

## Rails checklist (must hold in any shipped NoporIS surface)

- [x] Never over-claims privacy on the Google side — "**separation + convenience, not privacy**".
- [x] Labels the far persona **less-private / non-attestable**; `tier` pinned.
- [x] States that **root / an unlocked or compromised host defeats it**.
- [x] Never called **"Postern OS"**; NoporIS is an app on stock Android.
- [x] Cross-persona crossings **default DENY**; NoporIS never opens one itself.
- [x] Kill-switch drops the span and **never destroys sealed wallet state**.
- [x] Carries the standing disclaimers: **UNAUDITED / reference-prototype**, **coin
      worthless / not a security**, **ownerless base ⟂ owned products**, **personal-free**,
      **not legal advice**.
- [x] Trademark: **NoporIS/Nopor** needs formal clearance before the mark is committed.

---

*Design and scaffold only; UNAUDITED. Do not treat any file here as a security control.*
