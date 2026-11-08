<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Postern Enterprise — deployment, signed builds & SLA support tooling

Tooling and documentation for the Postern **Business / Enterprise** revenue
line described in the disclaimer and in `docs/EVOLUTION.md`: **"deployment and
signed/notarized build channels, priority/SLA support."** It is the classic
honest OSS model — the free build is always buildable from source; the paid
thing is **work and assurance**, never the token.

## The model, stated honestly

- **Personal products stay free.** Always. The community edition is free and
  buildable from source. (The community edition is **not** "Postern OS".)
- **Business = free 6-month evaluation, then a paid licence** (paid in **fiat**,
  not the coin). The **coin is not a security** and is never the billing
  instrument.
- **Support / SLA is the paid work.** You buy a response-time commitment and
  hands-on help, not a promise that any given bug is instantly solvable.
- **No telemetry.** Nothing here tracks users. Support intake is minimal-data,
  ticket-driven, and privacy-preserving by construction.

## What's here

| Area | Directory | Docs |
|---|---|---|
| Signed / notarized build channel | [`signing/`](signing/) | [`signing/SIGNING.md`](signing/SIGNING.md) |
| Deployment packaging (container + Nix) | [`packaging/`](packaging/) | [`packaging/PACKAGING.md`](packaging/PACKAGING.md) |
| SLA / support intake scaffold | [`support/`](support/) | [`support/SUPPORT.md`](support/SUPPORT.md) |
| Deployment guide | — | [`DEPLOYMENT.md`](DEPLOYMENT.md) |
| Support model & SLA | — | [`SLA.md`](SLA.md) |

## Honesty rails (apply to everything here)

- **Not** secure, audited, attested, or production-ready. This is beta-grade
  tooling and skeletons.
- **Reproducible-by-design ≠ reproduced.** The packaging is written to rebuild
  deterministically; no bit-for-bit reproduction is claimed or attested here.
- **A signature proves origin + integrity only** — not that binaries match
  source, and not attestation.
- **Operator-run where real infra/keys are involved.** Signing keys, container
  registries, Nix hosts, notarization credentials, and ticket storage are all
  operated by you, not run in this repo. No real keys are committed; a clearly
  marked **DEV/SAMPLE** key exists only to exercise the flow.
- **The coin is not a security.** Licensing and support are billed in fiat.

## Licensing

Dual-licensed **MIT OR Apache-2.0** (see [`LICENSE-MIT`](LICENSE-MIT) and
[`LICENSE-APACHE`](LICENSE-APACHE)), matching the rest of the project. Every new
source/doc file carries an `SPDX-License-Identifier: MIT OR Apache-2.0` header.

## Quick start (operator)

```sh
# 1. Verify a delivered build
signing/verify-build.sh -d ./delivery -P RWS…realkey…

# 2. Package it for self-hosting (container path)
cd packaging && podman compose up -d

# 3. Track an SLA ticket
support/sla-track.sh support/sample-ticket.json
```
