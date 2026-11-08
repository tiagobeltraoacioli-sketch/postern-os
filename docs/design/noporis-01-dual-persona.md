<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs -->

# NoporIS 01 — the dual-persona architecture

**Architect A4 · scope: define the two worlds and what the bridge actually is.**

> **Status: DESIGN / reference-prototype. UNAUDITED — certifies nothing about
> security.** Nothing here has booted on device. This document defines the
> component boundary and the relationships; the on-device orchestrator it
> describes **does not exist yet (UNTESTED)**.

---

## 0. Honesty rails (pinned — this doc may not soften them)

Carried verbatim from the scaffolds already in `apps/noporis-*` and enforced in
their code, not just prose:

1. **The Google-Play persona is the LESS-PRIVATE side, by construction.** It runs
   Google Play Services / GMS and **phones home to Google**. NoporIS sells
   **separation + convenience, not privacy** on that side. It can never be made
   private, sealed, or attested. Every surface that names it says "less private".
2. **`tier` is always `non-attestable` for the Google side.** No Seal, no measured
   boot, no padlock. No code path may relabel it attested
   (`noporis-gate` pins `tier` in `defaultState()`; `World::Noporis::may_show_attestation()` is `false`).
3. **Default-SAFE / deny-by-default.** The bridge is closed and the user is *not*
   standing on it unless they consented on purpose. Missing/garbage/absent state
   normalises to full-deny + not-consented.
4. **NoporIS is an app/control-plane on stock Android (or a host OS). It is NEVER
   "Postern OS".** It owns no kernel, bootloader, baseband, or TEE. Its isolation
   is the substrate's own (Android work-profile / LXC), only as strong as the
   kernel beneath it. A rooted / unlocked / kernel-compromised host defeats the
   separation. Sandboxed is **not** sealed.
5. **Respect Google/Android licenses.** No GMS redistribution — the user brings
   their own Google install. No SafetyNet / Play-Integrity circumvention — honest
   labelling instead. "Android", "Google", "Google Play", "Play Integrity" are
   used **nominatively only**; no affiliation, no fake attestation.
6. **The kill-switch drops the span but NEVER destroys sealed wallet state** on the
   near side (`sealedWallet.preserved` is fixed `true`).
7. **Naming.** "Nopor / NoporIS" is a **PROPOSED coined mark, pending formal
   trademark clearance** (shares the "NOPOR" filing root). "Postern" is the suite
   brand. The Kalinov crossing is kept neutral — a passage between two worlds that
   **both persist**, never a "world of the dead". Guardian is **Yagabona** (coined),
   never the registered "Baba Yaga". The coin (BLCH) is not a security, buys no
   software; personal use is free. Not legal advice.

Matches the public marketing copy in `bp-wt-site/site/build.js` lines 574 & 903
("NoporIS — the bridge … a dual-persona layer … the Google side is honestly the
less-private side … separation, not privacy … respects Google/Android licenses …
reuses Porog's managed-profile plumbing without forking it; deny-by-default,
per-capability"). The goal of this doc is to make that copy *real*, not contradict it.

---

## 1. The two personas, precisely

A "persona" (also "world") is **which paired peer a signer/data frame arrived on,
given a human name** — it is *not* a new signer or crypto primitive (see
`noporis-signer-glue/src/world.rs`, `noporis-bridge-glue/src/persona.rs`). The
world label is **derived from the pairing**, never from anything the requester
controls, so a compromised far side cannot mislabel its own world.

Android permits **exactly one managed profile per user**, so the folklore (two
worlds, one guarded crossing) maps **1:1** onto the mechanism — there are two
personas, no more, and no sixth "everything" lane.

| | **NEAR / clean persona** | **FAR / Google-Play persona** |
|---|---|---|
| Enum | `Persona::Clean` / `World::Porog` | `Persona::GooglePlay` / `World::Noporis` |
| What it is | The hardened, de-Googled, **wallet-side** world. Where the sealed post-quantum base and Postern apps live. | A **real Google-Android** environment with GMS / Google Play enabled, that the user brings themselves. |
| Trust level | **Key-attested device** where a TEE/StrongBox exists (`seal::verify_report`, fail-closed). Hardened, **not** measured-boot, **not** anonymous. | **`non-attestable`, always.** No Seal, no padlock. **Phones home to Google.** The **less-private** side. |
| What runs in it | Postern Wallet + workspace apps through the one `postern-sdk` FFI facade; Tor-only, fail-closed egress. | Whatever Google apps the user wants (banking, Wallet/Pay, messaging, work MDM). Normal networking. |
| Egress identity | Fail-closed Tor-only (`porog-tor-glue` / `noporis-tor-glue` clean identity). | Normal networking. May get its **own** circuit-isolated Tor identity for Tor-*layer* un-correlation only — but GMS phones home regardless (`noporis-tor-glue` `CORRELATION_CEILING` / `GMS_OUT_OF_SCOPE`). |
| Attestation shown? | **Only here**, and only where a genuine `Verdict::Genuine` is possible. | **Never** — a padlock here is the theater we reject. |

**Key point about "one keyring, two worlds":** the phone holds *one* Postern
keyring but presents it at **one door at a time** — two *independent* pairings,
one per world (`PairingRecord` peer-pin + forward-secret `session_root` each).
The signer core signs against *a session + a named peer + exact bytes*; the world
badge is folded into the existing `peer_device` WYSIWYS field at construction
(no new wire data), so the prompt reads e.g.
`"NoporIS · Google-Play side — less private · Tiago's Chromebook"`.

---

## 2. What NoporIS IS — the central resolution

The scaffolds today carry **two coexisting substrate framings** for the far
persona, and this is exactly the ambiguity A4 must resolve:

- **Stock-Android framing** (`noporis-bridge-glue/persona.rs`, `noporis-gate`
  schema, `noporis-signer-glue/world.rs`): the Google-Play persona is a **second
  managed profile on the same stock-Android handset** as Porog. "One managed
  profile per user … maps 1:1."
- **Waydroid/desktop framing** (`noporis-switcher/index.html` lines 684, 781):
  the Google-Play persona is a **Waydroid guest on the OS/desktop surface**, gated
  by `gate-store.mjs` + `postern-policy`, with clipboard → `wl-clipboard` and the
  rest → Waydroid/LXC device passthrough.

### Resolution: NoporIS is the dual-persona CONTROL-PLANE, not a container and not Porog.

**NoporIS is the substrate-agnostic orchestration layer** — persona lifecycle +
switch UX + deny-by-default consent kernel + the cross-persona data bridge — that
**drives whichever persona-isolation substrate the device offers**. It is *not*
itself the isolation boundary. It has **two substrate back-ends**, selected by
device tier, presenting the *same* two-persona model and the *same* honesty rails:

| Device tier | NEAR persona substrate | FAR (Google-Play) persona substrate | NoporIS drives it via |
|---|---|---|---|
| **Stock Android** (user's own phone) | **Porog** — the managed-profile container (A1–A3) | A **second managed profile** (Android's own work-profile mechanism) | Porog's cross-profile plumbing (**reused, not forked**) |
| **Postern-OS / desktop** (community edition) | The sealed host base | A **Waydroid guest** (LXC/AOSP+GMS) | `apps/sloboda` wrapper's bridge state + kill-switch (A7/A8) |

So, crisply:

- **NoporIS ≠ Porog.** Porog is the **door** — one *near-side hardened world
  substrate* on stock Android. NoporIS is the **bridge** — the control-plane that
  spans *two* personas and moves consented items between them. On a stock phone,
  NoporIS **reuses Porog's managed-profile plumbing without forking it**; the far
  persona is a second work profile that NoporIS orchestrates through the same DPC
  surface Porog already speaks.
- **NoporIS ≠ Waydroid.** Waydroid (`apps/sloboda`, A7/A8) is the
  **non-attestable community-edition substrate** that NoporIS uses as the *far
  persona* on the desktop/OS tier. NoporIS consumes its read-only bridge-state /
  kill-switch seam; it does not own or boot the container.
- **NoporIS therefore spans device tiers** — same personas, same consent kernel,
  same UX — over **either** the managed-profile substrate **or** the Waydroid
  substrate. The `tier` field in gate state records which honesty posture applies;
  the far side is `non-attestable` in **both** back-ends.

### Component boundary (what A4 owns vs. consumes)

NoporIS's own, net-new surface (owned by the NoporIS architects):

- **The consent kernel** — `apps/noporis-gate/` (`gate-store.mjs` +
  `gate-state.schema.json`): deny-by-default per-capability crossings + first-entry
  bridge consent + kill-switch + `tier` pin. The canonical state shape.
- **The cross-persona data bridge** — `apps/noporis-bridge-glue/` (Rust): carries an
  approved crossing's payload between the two personas over the pairing channel,
  double-gated (a live `CapabilityGrant` to send + a live `GateConsent::Allow` to
  deliver), zeroizing, fail-closed.
- **The persona switch UX** — `apps/noporis-switcher/` (front-end): the two-world
  switcher + guarded-crossing panel + world-badged signer prompt + kill-switch.
- **The per-persona egress identity seam** — `apps/noporis-tor-glue/` (Rust):
  one shared client-only Tor, two disjoint circuit families (Tor-layer
  un-correlation only).
- **The world vocabulary for the signer** — `apps/noporis-signer-glue/` (Rust):
  `World` display/policy vocabulary + two-pairings + kill-switch, no key material.
- **THE MISSING PIECE (A4's headline gap): the on-device orchestrator.** None of
  the above is wired to a real device. There is **no** process that: (a) creates /
  attaches the far persona on the chosen substrate, (b) reads the gate state and
  opens the concrete cross-profile / Waydroid plumbing for each `Allow`, (c)
  services the switch, (d) executes the kill-switch. Every scaffold README says
  "the on-device wrapper does not exist yet (UNTESTED)." Defining and building that
  orchestrator is the spine of making NoporIS functional.

Consumed (owned by others, **never edited** here), via public APIs only:

- `integration/pairing` — `Channel` (`seal_frame`/`open_frame`), `Transport`,
  `PairingRecord`: the PQ-hybrid (ML-KEM-1024‖X25519), SAS-anchored,
  mutually-authenticated, replay-guarded pipe + peer pin.
- `integration/signer-protocol` — `SessionId`, `fresh_nonce()`, `RequestCounter`,
  `ConsequenceTier`, `Wysiwys`: the consent-model freshness primitives.
- `crates/postern-policy` — `Decision::{Allow, Deny}`, default `Deny`.
- `crates/postern-sdk` — `seal::verify_report` (fail-closed: no anchor ⇒
  `Unverified`, never accepted) — the **only** attestation surface, Porog side only.
- `crates/postern-tor` — `PosternTor` / `for_identity()` / `IsolationToken`.
- **Porog** (A1–A3, Kotlin/DPC + `porog-tor-glue`) — the managed-profile substrate.
- **Waydroid wrapper** (A7/A8, `apps/sloboda`) — the community substrate.

---

## 3. The persona-switch UX + consent model

**Switch UX (one keyring, one door at a time).** The switcher presents a single
keyring at exactly one world at a time; the span is animated as a **bridge deck
extending**, never a door swinging (a switch is *not* a merge). Switching worlds
re-points which pairing the signer serves; it moves **no data** by itself.

**Two independent consent gates before anything crosses:**

1. **First-entry bridge consent** (`consent.accepted` in gate state). The user must
   read the honest disclosure — *the far side is less-private, phones home to
   Google, non-attestable* — and accept to "stand on the bridge" at all. Default
   `scope = "session"` (re-ask next boot); `"persistent"` is opt-in. Default DENY:
   not standing on the bridge unless entered on purpose.
2. **Per-capability crossing** (`crossings.{clipboard,files,mic,camera,location}`).
   Each is a **covert channel if silently on**, so each defaults to DENY, is opened
   only by an explicit disclosed toggle the user throws, and is individually
   revocable. `mic`/`camera` sit behind a **second micro-consent** (loudest tier).
   Anti-round-up: nothing crosses that the user did not hand across; a closed/absent
   crossing exposes **nothing**.

**Runtime crossing (defense in depth, `noporis-bridge-glue`):** the near side won't
`send_crossing` without a live `CapabilityGrant`; the payload is sealed into the
pairing `Channel` (AEAD, per-direction counter, session AAD); the far side won't
`deliver` without an independent `GateConsent::Allow` (deny-by-default), after a
`CrossingGuard` freshness check (nonce / monotonic counter / session binding).
Deny ⇒ fail closed, nothing crosses. Delivered payloads are zeroizing.

**Kill-switch.** `killSwitch.engaged = true` drops the span immediately — closes
every crossing, stops the far side — and **never touches the sealed base / wallet
keys** (`sealedWallet.preserved` fixed `true`). On the Waydroid substrate this maps
to the wrapper's existing kill (stop container + clear session runtime, image
intact); on the managed-profile substrate, to revoking the cross-profile grants
and, at most, pausing the work profile.

---

## 4. Identity model — one Postern identity, no private-side leak

**One keyring, two pairings.** The user's Postern identity is the sealed
post-quantum keyring on the **near** side. It is presented to each world through a
**separate pairing** (`PairingRecord`, peer-pinned, forward-secret `session_root`).
The Google-Play persona is a *pairing peer*, exactly like an external desktop — it
is **never** handed the sealed base, private keys, or seed.

**Non-leak invariants:**

- The far persona receives **only** what crosses an explicit per-capability grant —
  a clipboard blob, a file, a device sample — **never** identity material.
- The world label the signer shows is **derived from which pairing the frame
  arrived on**, so the Google side cannot spoof itself as the hardened side, and a
  transfer prompt on the Google pairing is badged "less private" by construction.
- A `GrantScope::LoginTo { org }` never covers a transfer — a login grant to the
  Google side cannot move funds.
- Egress: the far persona may get its **own** Tor identity (`noporis-tor-glue`), but
  the ceiling is pinned — this un-correlates *circuits only*, not device identity
  (same IMEI/SIM/IP/serial), and GMS phones home over normal networking regardless.
  So identity-separation is honestly **separation of worlds on one device**, not
  anonymity.

The private side is therefore **structurally** unable to leak into Google's: there
is no code path that hands identity across, and the only things that cross are the
five capability payloads the user explicitly lent.

---

## 5. Functional proof — what makes NoporIS "functional" end-to-end, and where

NoporIS is "functional" when this full loop runs and is observed:

> **create a persona → consent → a single item crosses → kill-switch closes it →
> re-verify nothing crosses.**

Concretely, one scripted E2E scenario:

1. **Persona created/attached.** The far (Google-Play) persona exists on the chosen
   substrate (a second managed profile provisioned via the DPC; **or** a Waydroid
   guest started). *Proof today:* substrate mock — `test/mock-waydroid` +
   `noporis-gate` `defaultState()`; **on device** this is the UNTESTED step.
2. **Standing on the bridge.** `consent.accepted = true` with a recorded scope, only
   after the honest disclosure. *Proof:* `noporis-gate/test-store.mjs` (34 checks).
3. **One consented item crosses.** Open exactly `crossings.clipboard`; run one
   `send_crossing` → `receive_crossing`; observe the payload delivered on the far
   side and **nothing else** exposed. *Proof:* `noporis-bridge-glue` `cargo test`
   (16 tests: happy path + every fail-closed branch) and `cargo run --example
   crossing` (printed end-to-end guarded crossing).
4. **Kill-switch closes it.** Set `killSwitch.engaged`; assert every crossing now
   denies, the far side is dropped, and `sealedWallet.preserved` is still `true`.
   *Proof:* `noporis-gate/test-store.mjs` kill-switch + wallet-preserved assertions;
   `noporis-bridge-glue` fail-closed branch.
5. **Fail-closed re-verify.** Corrupt/blank the state file; assert full-deny +
   not-consented. *Proof:* `noporis-gate` `normalize()` trust-boundary tests.

**Where it must run to count as real (UNTESTED gaps):**

- The reference-kernel + bridge-glue + switcher tests run **offline, in CI** (node
  + `cargo test`) — they prove the control flow and every honesty rail, and prove
  **nothing** about device behaviour.
- The end-to-end loop is only *real* on **aarch64 hardware**: (a) stock Android with
  a real second managed profile + Porog's DPC, cross-profile clipboard/file/device
  APIs actually gated; **or** (b) a Postern-OS/desktop host with a binder-capable
  kernel booting a real Waydroid guest (`apps/sloboda` §"Only confirmable on
  a real Waydroid device"). Until the **on-device orchestrator** (§2) exists and
  runs there, NoporIS remains a validated *scaffold*, not a functional product.

---

## 6. Phased dev task-list

**Phase 0 — contract freeze (this doc + reconciliation).** Ratify §2's resolution:
NoporIS = substrate-agnostic control-plane with two back-ends. Reconcile the
switcher copy (lines 684/781) so both the managed-profile and Waydroid substrates
are named as *back-ends of one control-plane*, not competing definitions. Freeze the
`noporis-gate` state shape as the single source of truth both back-ends read.

**Phase 1 — the on-device orchestrator (the headline gap).** Define and build the
process that reads gate state and drives a substrate: a `Substrate` trait with two
impls — `ManagedProfileSubstrate` (over Porog's DPC seam) and `WaydroidSubstrate`
(over `apps/sloboda`'s read-only bridge-state + kill-switch). Deny-by-default
mapping of each open crossing to concrete plumbing; nothing for a closed crossing.

**Phase 2 — wire the bridge to the substrate.** Connect `noporis-bridge-glue`'s
`send/receive_crossing` to real cross-profile / Waydroid device passthrough behind
each `GateConsent::Allow`. Keep the double-gate; keep zeroizing delivery.

**Phase 3 — two-pairings switch + world-badged signer on device.** Stand up the two
independent `PairingRecord`s, serve the signer in one world at a time, derive the
world badge from the pairing, block prompt/world mismatch.

**Phase 4 — per-persona egress.** Bind `noporis-tor-glue`: clean side fail-closed
Tor-only; Google side its own circuit family, with the correlation ceiling surfaced.

**Phase 5 — E2E harness on hardware.** Run §5's five-step loop on both substrates on
real aarch64; record what passed vs. what stayed UNTESTED; keep every honesty label
matching observed behaviour (confirm Play Integrity STRONG fails; badge "less
private" everywhere it appears).

---

## 7. Top risks

1. **Substrate ambiguity ships as a contradiction.** If the two framings aren't
   reconciled (Phase 0), the product claims two incompatible things. Mitigated by
   §2's one-control-plane / two-back-ends resolution.
2. **The orchestrator never gets built.** Everything today is offline scaffolding;
   the piece that makes it real (§2 headline gap) is the largest unstarted surface.
3. **Managed-profile isolation is only as strong as the kernel.** A rooted/unlocked
   host defeats the separation on both substrates; must stay labelled, never sold as
   privacy.
4. **License/attestation drift.** Any drift toward GMS redistribution, Play-Integrity
   circumvention, or showing a padlock on the Google side breaks the rails and the
   Google-mark nominative use. Enforced in code (`tier` pin, `may_show_attestation`),
   must stay enforced.
5. **Identity leak via an over-broad crossing.** A "files" or "clipboard" crossing
   left persistent is a covert channel; default-DENY + session scope + kill-switch
   are the guardrails, and must not regress.
6. **Trademark.** "Nopor/NoporIS" is unclaimed; the "less private" and "not Postern
   OS" labels are load-bearing legal posture.
