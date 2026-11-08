<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
-->

# Bloch — org internal messenger (Postern Labs, **Business/Enterprise edition only**)

An internal employee messenger — **channels + DMs**, org-scoped membership — that
rides the Postern Messenger E2EE core and refuses to run outside a valid
enterprise license. Reference prototype, **UNAUDITED**, pre-production.

> **This app is enterprise-only.** It is not part of the free personal suite and
> it never fabricates a "licensed" state. Your personal Postern apps and your
> data are unaffected by anything here.

## What it is

- **Org messenger** — `src/comms-core.mjs`. Channels and DMs whose membership is
  the org roster. It implements **no crypto**: end-to-end encryption of message
  bodies is owned by `crates/postern-messenger` (Matrix + vodozemac/**Megolm**),
  which this app **references, never forks**. Every conversation is tagged with
  that crate's `InternalE2ee` tier badge.
- **Org-scoped membership** — drawn from the enterprise **sub-access** model
  (`enterprise/features/sub-access.mjs`): each active sub-access grant is a
  person. Unlimited seats under one master, **no per-user server login**.
- **Enterprise-license gating** — `src/license-bridge.mjs`. Plugs into
  `enterprise/features/license-hook.mjs` and an injected `window.PosternLicense`.
  **Fail-closed**: a token with no offline verifier is `unverified` and the app
  refuses; a forged/partial gate never becomes corporate. It contains no crypto
  and no verification of its own — it defers to the license layer.
- **Transparency banner + honest privacy panel** — `src/transparency.mjs`.
  States plainly what is E2EE (message **bodies**) and what is **not** hidden
  (metadata: who/when/membership), plus the employer-visibility wrinkle from
  `enterprise/features/privacy.mjs`. It refuses to claim "100% private" — Bloch
  is an **employer-run tool**.
- **Compliance hook** — `src/compliance-hook.mjs`. The seam where the compliance
  layer (`enterprise/comms/compliance/`, owned by another dev) injects the
  employer's **retention / disclosure** text via `window.PosternCommsCompliance`.
  Policy text is **not hardcoded here**. If nothing is wired in, the panel says
  the posture is **UNKNOWN** and to ask an admin — silence is never rendered as
  "private".

## Files

```
app/
  index.html            self-contained, framework-free UI (imports the ES modules; no network)
  src/
    comms-core.mjs       channels/DMs + org-scoped membership, bound to the E2EE tier
    license-bridge.mjs   fail-closed enterprise gate (license-hook + window.PosternLicense)
    compliance-hook.mjs  injection seam for the compliance layer's disclosure text
    transparency.mjs     transparency banner + honest privacy panel model
  self-check.mjs         node smoke test (no framework)
  core-rs/               thin Rust core over postern-messenger's SecurityTier wall
```

## Verify

```sh
# JS
node --check src/*.mjs self-check.mjs
node self-check.mjs                     # all checks pass

# Rust (standalone crate, own [workspace])
cd core-rs && cargo check && cargo test
```

The UI is fully local (`connect-src 'none'`). Open `index.html` in a browser; use
the demo license/compliance switches (they stand in for the real
`window.PosternLicense` / `window.PosternCommsCompliance` injections a deployment
provides) to see the fail-closed refusal and the transparency panel.

## Rails (honest boundaries)

- **Enterprise-only.** Refuses outside a valid corporate-master or business-tier
  license; never fakes "licensed".
- **E2EE where it holds.** Bodies are Megolm-E2EE via `postern-messenger`;
  **metadata is org-visible**, Megolm is classical (not post-quantum), and this
  build is a reference prototype with no persistence/verification guarantees.
- **Honest about retention & employer-visibility.** The compliance layer owns the
  disclosure; absent it, the posture is stated UNKNOWN.
- **Adherence-by-design, not certified. Unaudited.** Not legal advice — real
  compliance needs a DPO + counsel.
- The coin is **not a security** and buys no software.
- The compliance layer at `enterprise/comms/compliance/` is owned by another dev
  and is **not touched** by this app.
```
