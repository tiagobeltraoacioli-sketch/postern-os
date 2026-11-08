<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs -->

# Consiglio console — HOSTED deploy wiring

**STATUS: DEFERRED / VM-host-service-gated. WRITTEN + host-tested, NOT deployed. UNAUDITED.**

This folder is the *shipping form* of the Consiglio console: a container image
and a Fly app config that run `http/server.mjs` as a long-lived HTTP server.

## What is PROVEN vs what is DEFERRED

- **HOST-proven now** — the runtime and its enforcement. On the build host,
  `node enterprise/cloud/services/console/http/self-check.mjs` (and the sibling
  `console/self-check.mjs`) run **GREEN** with the **real** pinned
  `consiglio-verify` binary: a real hybrid-PQ wallet login, dual-control +
  Brewer–Nash SoD refusing self-approval and same-side approval, a *separated*
  admin committing, offboard killing live sessions, and durable state surviving a
  kill-and-restart. The enforcement path is real, not declared.
- **DEFERRED (needs an operator)** — the *live hosted deploy*. Building this image
  and running it on a VM/host service (Fly, a Workers container, or a plain VM) is
  an operator step; it is not exercised in CI here. Nothing about this deploy is
  live until an operator runs it.

## Why this is a server, not a Cloudflare Pages asset

Wallet-login verification **spawns the native `consiglio-verify` binary** (hybrid
Falcon-1024 ‖ ML-DSA-65 via `bloch_crypto`). A browser or an edge Worker **cannot
run that binary**, so the console cannot ship as a static Pages asset — it must be
a host process that can `spawn()` the verifier. This is the honest reason the
shipped-service claim is host-service-gated rather than "deployed to Pages."

## Fail-closed provenance pin

The image bakes the verifier at `/opt/postern/bin/consiglio-verify` and sets
`CONSIGLIO_VERIFIER_BIN` to exactly that path. The bridge
(`consiglio-verifier.mjs`) then runs **only** that binary and refuses to fall back
to a `target/` scan. If the binary were missing, login **fails closed** — the
bridge throws; there is never a `"SIG(...)"` stub fallback.

## Operator runbook (DEFERRED — do not treat as done)

```sh
# From the repository ROOT (build context needs crates/ + enterprise/):

# 1. Build the image.
docker build -f enterprise/cloud/services/console/http/deploy/Dockerfile \
  -t consiglio-console .

# 2a. Run locally (auth-only; durable state in a named volume).
docker run --rm -p 8803:8803 -v consiglio_data:/data consiglio-console
#   curl localhost:8803/healthz   -> { ok:true, verifierAvailable:true, ... }

# 2b. Enable the seat/device verbs by mounting a master bundle.
docker run --rm -p 8803:8803 -v consiglio_data:/data \
  -v /path/to/master.json:/secrets/master.json:ro \
  -e MASTER_BUNDLE=/secrets/master.json consiglio-console

# 3. Fly.io (single machine; the file store is node-local).
fly launch --no-deploy --copy-config --name consiglio-console   # uses fly.toml
fly volumes create consiglio_data --region gru --size 1
fly secrets set MASTER_BUNDLE=/secrets/master.json              # optional
fly deploy
```

## Scaling caveat

The durable store (`store.mjs`) is a node-local atomic file store, so this config
pins a **single** machine (`min_machines_running = 1`, `auto_stop_machines =
false`). To scale horizontally, swap the file store for a shared backend behind
the **same** `snapshot()`/`{state}`, `onChange`/`{records}`, audit-load/save seams
— the service factory takes an injected store, so no crypto or route code changes.

## Rails

UNAUDITED reference prototype. This DEMONSTRATES controls that ENABLE
compliance/governance — it is NOT compliance and NOT legal advice. Audit is
tamper-EVIDENT (SHAKE-256 chain), not tamper-proof. Billing is fiat only; the coin
is never billed. Privacy is LGPD/GDPR-minimal (public keys + metadata only).
