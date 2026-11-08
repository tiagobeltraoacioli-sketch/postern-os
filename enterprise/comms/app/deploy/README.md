<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs -->

# Bloch (comms-app) — deploy

Container/Fly deploy scaffold for **Bloch**, the org-internal messenger at
`enterprise/comms/app/`. Mirrors the shape and disclosures of the hosted
"cloud" edition image at [`../../../cloud/image/`](../../../cloud/image/)
(`Containerfile` + `build-image.sh` + `fly.toml`), adapted for the fact that
Bloch is a **static, framework-free app** (no server of its own — the app's
[README](../README.md) literally says "open `index.html` in a browser") rather
than a compiled service binary.

> **Standing caveats (same as the cloud image).**
> - **Reference prototype, UNAUDITED, pre-production.** Not hardened beyond
>   what is shown here. Not production-ready.
> - **Reproducible-by-design is NOT reproduced.** Base pinned by digest,
>   `SOURCE_DATE_EPOCH` honored — rebuild + `sha256sum`/`diffoscope` compare it
>   yourself; no claim of independent reproduction is made here.
> - **Hosted is less private than self-hosting or on-device.** Bloch's own
>   transparency panel (`src/transparency.mjs`) already refuses to claim "100%
>   private" — it is an employer-run tool where metadata stays org-visible.
>   Running it as a hosted container is a further, disclosed step in the same
>   direction (the operator can additionally observe request traffic/timing).
> - **No secrets baked in.** This image ships no license key, no crypto key,
>   no compliance policy text — those are injected at runtime
>   (`window.PosternLicense`, `window.PosternCommsCompliance`) by whoever
>   operates the deployment. Without them the app's own fail-closed gate
>   refuses to present itself as licensed (see `src/license-bridge.mjs`).
> - **The coin is not a security; licenses/support are billed in fiat.**

## Why the image needs more than `comms/app/`

Bloch's ES modules import across sibling directories with relative paths that
escape `comms/app/` — e.g. `../../features/sub-access.mjs`,
`../../features/license-hook.mjs`, `../../compliance/audit-trail.mjs`. So the
image's webroot is `enterprise/`, not `enterprise/comms/app/`, and the
`Dockerfile` `COPY`s three subtrees: `enterprise/features/`,
`enterprise/comms/app/`, `enterprise/comms/compliance/`. It copies **only**
those — see [`.dockerignore`](.dockerignore) — nothing else in the monorepo is
reachable from Bloch's own module graph.

## Files here

| File | Role |
|---|---|
| [`Dockerfile`](Dockerfile) | Deployable image (pinned base digest, non-root, egress-controlled, telemetry off — same posture as the cloud image's `Containerfile`) |
| [`server.mjs`](server.mjs) | The one piece of "server" code Bloch doesn't otherwise have: a zero-npm-dependency static file server (`node:http` + `node:fs` only), `/healthz`, path-traversal guarded |
| [`fly.toml`](fly.toml) | Fly config for a staging/demo deployment |
| [`.dockerignore`](.dockerignore) | Keeps the build context to the three subtrees actually `COPY`'d |

## Build (local only — this is as far as this authoring pass goes)

Build context **must be the repo root**, because the image needs
`enterprise/features/` and `enterprise/comms/compliance/`, which live outside
`comms/app/`:

```sh
# from the repo root
docker build -f enterprise/comms/app/deploy/Dockerfile -t postern-comms-app:local .
# podman works too:
podman build -f enterprise/comms/app/deploy/Dockerfile -t postern-comms-app:local .
```

Pin a real base + provenance the same way the cloud image does:

```sh
docker build \
  --build-arg BASE_DIGEST=sha256:<vetted-node:22-bookworm-slim-digest> \
  --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct 2>/dev/null || echo 0)" \
  -f enterprise/comms/app/deploy/Dockerfile -t postern-comms-app:local .
```

Run it locally to smoke-test before anything touches Fly:

```sh
docker run --rm -p 8080:8080 postern-comms-app:local
curl -sf http://localhost:8080/healthz
curl -sf http://localhost:8080/ | head -5     # redirected to /comms/app/index.html
```

## Deploy — NOT done here, operator-run, explicit and separate

Nothing in this directory pushes an image or calls `fly deploy`/`fly launch`.
That is a deliberate, later, human step:

```sh
# from the repo root, once you have reviewed fly.toml and this README
fly launch --config enterprise/comms/app/deploy/fly.toml --no-deploy   # register the app, review generated settings
fly deploy . --config enterprise/comms/app/deploy/fly.toml \
              --dockerfile enterprise/comms/app/deploy/Dockerfile
```

## Status of this authoring pass

- `Dockerfile`, `server.mjs`, `fly.toml`, `.dockerignore`, this `README.md`:
  **authored**, reviewed by inspection (labels/env/healthcheck/non-root/COPY
  set cross-checked against Bloch's actual import graph).
- `server.mjs` verified standalone with plain node (no docker daemon
  available on the authoring host): `/healthz`, `/`, cross-directory sibling
  imports, path-traversal, and dotfile/percent-encoded-dotfile requests all
  behave correctly.
- `docker build -f enterprise/comms/app/deploy/Dockerfile -t postern-comms-app:host-check .`
  is **build-pending** — it has NOT been run. It still needs to be executed
  on a box with a running docker (or podman) daemon, which the authoring host
  does not have; `fly.toml` was only validated by TOML-parsing it and
  cross-checking its shape against the `enterprise/cloud/image/` console
  precedent, not by an actual build/deploy. **No `fly deploy`, no registry
  push, no live endpoint** — that stays a separate, explicit,
  operator/Bucket-C step, alongside the still-pending `docker build` itself.
