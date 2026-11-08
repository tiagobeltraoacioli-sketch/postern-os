<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# NoporIS — per-persona Tor egress identity (this crate's part)

**Status: DESIGN / reference-prototype. UNAUDITED. No security claim.**
NoporIS is an app on stock Android; it is **never "Postern OS."** The coin is
worthless and **not a security**; personal use is free; this is **not legal
advice.** Hardened, **not anonymous**.

> **Naming.** **NoporIS / Nopor** is a **PROPOSED** name pending formal trademark
> clearance (shares the existing "NOPOR" filing root) — a sanity note, not
> clearance. "Postern" is the suite brand.

## What this crate does

NoporIS bridges **two personas** on one handset — a **clean/business** persona and
a **Google-Play** persona (the platform enforces exactly two: one managed profile
per user). This crate (`noporis-tor-glue`) gives **each persona its own
circuit-isolated Tor identity**:

- Each persona is derived from **one** shared, client-only
  `postern_tor::PosternTor` via `for_identity()` **plus** its own
  `IsolationToken`. Two personas ⇒ **two disjoint circuit families** from one Tor.
- The single value delivered: the two worlds' egress **does not trivially
  correlate at the Tor layer** — no shared circuit, no shared exit relay, no
  shared-timing linkage between "the clean world" and "the Google world."
- For the **clean** persona, egress is **fail-closed and Tor-only** (the same rule
  as `porog-tor-glue::egress_decision`, generalized per persona): no live circuit
  ⇒ **no egress**, no clearnet fallback exposed anywhere in this crate.

This is **not** `apps/noporis-bridge-glue` (the N-channel *cross-persona* bridge).
This crate is only the **egress / Tor-identity** seam.

## The honest ceiling — do not soften (pinned in `src/lib.rs`)

Per-persona Tor isolation is narrow. The exact words live in code as
`CORRELATION_CEILING` and `GMS_OUT_OF_SCOPE`:

- **Tor-LAYER un-correlation only.** Distinct `for_identity()` handles stop an
  exit/destination from linking the personas *by shared circuit*. That is the
  whole guarantee.
- **It does NOT stop device- or network-level correlation.** Same public IP
  (unless *every* persona is fully Tor-routed — the Google persona, by design, is
  **not**), same **IMEI / SIM / phone number / hardware serial**, same modem. A
  carrier, Google, or a network observer can still tell the two personas are **one
  physical phone.** Separation of *circuits* is **not** separation of *device
  identity*.
- **The Google-Play persona is the LESS-PRIVATE side, by construction.** Its GMS
  egress **phones home regardless**, over the persona's **normal networking** —
  **not** this glue's Tor identity. This crate gives that persona a distinct Tor
  identity only for the traffic the app *chooses* to route over Tor; it **cannot**
  contain GMS. **Separation + convenience, not privacy** on the Google side.
- **Client-only Tor.** `postern-tor` connects *to* the network / `.onion`
  services; it does **not** host one. No hosting path here.
- **Userland, not a kernel boundary.** The egress gate is
  `EnforcementMode::ByConstruction` — an in-process check. The real cryptographic
  boundary between the two worlds is the **managed profile's** separate FBE keys +
  SELinux, which this crate does **not** implement and must never claim. A
  rooted / kernel-compromised host defeats all of it.
- **Not the attested workspace.** NoporIS attests the **phone** (key-attested
  device), **not the persona/workspace.** Never "measured-boot persona."

## API shape

Pure policy (always compiled, CI-fast):

- `Persona::{Clean, GooglePlay}` with honest flags — `is_tor_only()`,
  `gms_phones_home()`, `honest_label()`, `containment_caveat()` (the one-line
  headline caveat), `containment_caveats()` (the **full** ordered set).
- `persona_egress_decision(persona, tor_ready) -> Decision` — clean = fail-closed
  Tor-only; Google-Play = `Allow` (normal networking by design, **not** a privacy
  claim).
- `persona_egress_note(persona, tor_ready) -> (Decision, caveat)` — the one-line
  render; the Google persona's `Allow` never shows without its headline
  `GMS_OUT_OF_SCOPE`.
- `persona_egress_full_note(persona, tor_ready) -> (Decision, &[caveat])` — the
  full render: the Google persona's `Allow` carries **both** `GMS_OUT_OF_SCOPE`
  **and** `CORRELATION_CEILING` (GMS phones home *and* the Tor identity it gets for
  chosen traffic only buys Tor-layer un-correlation). Never rounds down.
- `honest_enforcement_label()` / `egress_can_claim()` — the anti-round-up guard,
  delegated verbatim to `postern-policy`.

Live Tor path (feature `live`, pulls `arti`, **not built in this sandbox**):

- `PersonaTor::for_persona(&shared, persona)` — one persona's isolated identity.
- `PersonaWorlds::{bootstrap, from_shared}` — **both** personas' disjoint
  identities from one shared client-only Tor. The headline: two worlds, two
  circuit families, one Tor.
- `PersonaTor::connect(host, port)` — Tor-isolated stream **after** the fail-closed
  gate allows it; for the Google persona this covers only app-chosen traffic, never
  GMS.

## What stays DESIGN until proven

- The live Tor path is feature-gated and unbuilt here, exactly as
  `postern-tor`'s own live bootstrap is an ignored integration test. Circuit
  isolation is asserted by construction (`for_identity()` + per-persona token); it
  is proven on-device, not in this sandbox.
- Anything about the *profile* boundary (FBE/SELinux) belongs to the NoporIS DPC,
  not this crate. This crate only routes egress and labels the ceiling.
