<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# NoporIS — persona switcher + bridge panel (reference front-end)

**Status: DESIGN / reference-prototype. UNAUDITED — certifies nothing about
security.** Self-contained, dependency-free, CSP-strict single-file app in the
same shape as the other `apps/*` (e.g. `apps/sloboda-gate`,
`apps/izbushka`). It opens **no** network (`connect-src 'none'`); a mock state
persists only to this browser's `localStorage`.

## What it is

The UI for the **guarded crossing** between two worlds that both keep existing:

- **Porog — the guarded _door_** into the hardened world (managed profile on
  stock Android; key-attested device, not a measured-boot workspace; Tor-only).
  A separate product; not edited here.
- **NoporIS — the guarded _bridge_** (the Kalinov crossing) to a second persona:
  a Google-Play / business side. **`tier = non-attestable`, always**, and badged
  **"less private"** wherever it appears.

The page renders: the two-world **switcher** (one keyring, presented at **one**
door at a time — the span is animated as a bridge deck extending, never a door
swinging); the **guarded-crossing bridge panel** (per-capability levers —
clipboard / files / mic / camera / location — each **default-DENY**, disclosed,
individually revocable, mic/camera behind a second micro-consent); **attestation
shown ONLY on the Porog side** and only where a real `Verdict::Genuine` is
possible (StrongBox vs TEE named honestly; key-attested **not** measured-boot);
the **two-pairings signer** with a **world-badged WYSIWYS** prompt (world label
derived from _which pairing the frame arrived on_, never requester text); the
**kill-switch** that drops the span without touching the sealed base/keys; and
an **anti-theater checklist** stated on the surface.

## Referenced by contract only (not edited)

- **N-gate / bridge state** — `apps/noporis-gate/gate-state.schema.json`
  + `gate-store.mjs` (schema id `postern.noporis-gate.state`): `tier` pinned
  `non-attestable`; `crossings.*` per-capability `{open, scope, openedAtIso}`
  objects, each default DENY; first-entry `consent` (`accepted`, `scope`);
  `killSwitch.engaged` "never destroys wallet state in the sealed base"
  (`sealedWallet.preserved` pinned `true`). This app's `localStorage` mock uses
  its own flat, switcher-local shape (booleans, not per-capability objects) —
  it does not persist the gate-store shape byte-for-byte; an on-device wrapper
  would map this mock's fields onto `noporis-gate`'s `crossings.*`. (The
  separate `apps/sloboda-gate` Waydroid community tier has its own,
  differently-shaped `bridges.*` state and is not the contract referenced
  here.)
- **N-signer** — `integration/signer-protocol` `Wysiwys { tier, sentence,
  can_move_funds, peer_device, confirmation_fragment }`, `ConsequenceTier`,
  `GrantScope::LoginTo { org }` (a grant never covers a transfer);
  `integration/pairing` `PairingRecord` (peer pins + forward-secret
  `session_root`). One phone, **two independent pairings**, one per world.
- **N-labeling / policy** — `crates/postern-policy` `Decision::{Allow, Deny}`,
  **default = Deny**. The real attestation surface is `crates/postern-sdk`'s
  `seal::verify_report` (fail-closed: no anchor ⇒ `Unverified`, never accepted).

## Honesty rails (enforced in code, not just copy)

NoporIS tier is always non-attestable (no path sets it attested); every bridge
defaults to DENY and normalises unknown/missing to DENY; the kill-switch stops
the far side and never touches the base/keys; the signer world label is derived
from the peer, not requester-supplied text; one world is live at a time. On
**stock Android**, never "Postern OS". Guardian is **Yagabona** (coined mark),
never the registered "Baba Yaga". The Kalinov crossing is kept neutral — a
passage between two worlds that **both persist**, not a "world of the dead".
Google / Android / Google Play / Play Integrity are named nominatively (real
third-party system; no affiliation, no fake attestation). The coin (BLCH) is not
a security and buys no software; personal use is free.

## Build / serve

`assemble-public.sh` step 2 copies each listed `apps/<name>/index.html` to
`public/apps/<name>/` (stripping any `postern-` prefix for the URL).
`noporis-switcher` is included in that list, so it publishes to
`/apps/noporis-switcher/`. Everything is inlined in the one file (no companion
assets), so no other build wiring is needed.
