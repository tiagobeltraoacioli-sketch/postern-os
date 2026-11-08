<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# BUILD-AND-DEPLOY.md — Postern Cloud (hosted) edition image

Operator runbook for the **cloud / hosted** edition: **build the image → push it
→ deploy it**. Every step here needs real infrastructure and credentials and is
**operator-run**. Nothing in this directory is executed, pushed, deployed, or
attested by the repository.

> **Standing caveats.**
> - **Reproducible-by-design is NOT reproduced.** These definitions are written
>   to rebuild deterministically (base pinned by digest, `SOURCE_DATE_EPOCH`,
>   egress-controlled assembly). No independent bit-for-bit reproduction is
>   claimed. Verify parity yourself (rebuild + compare digests, `diffoscope`).
> - **Hosted is less private than self-hosting.** Running this as a managed
>   service lets the operator observe traffic, metadata, and timing that a
>   self-hosted or on-device deployment would not expose to a third party. This
>   is a deliberate, **disclosed** trade-off — disclose it to your end users too.
>   For maximum privacy, self-host ([`../../deployment/packaging/`](../../deployment/packaging/))
>   or run on-device.
> - **No secrets are baked into the image.** Config and secrets are injected at
>   runtime and must never be committed.
> - **Telemetry is off** (`POSTERN_TELEMETRY=off`). No analytics, no phone-home.
> - Not secure, not audited, not attested, not production-ready. Reference
>   scaffold. The token is not a security; licences and support are billed in fiat.

## Files here

| File | Role |
|---|---|
| [`Containerfile`](Containerfile) | Deployable cloud image definition (pinned base digest, non-root, read-only-rootfs-friendly, egress-controlled, telemetry off) |
| [`build-image.sh`](build-image.sh) | Builds the image LOCALLY. **Does not push or deploy.** |
| [`compose.yaml`](compose.yaml) | Stack manifest to run the built image with least-privilege defaults |
| [`cloud-image.nix`](cloud-image.nix) | Optional Nix (`dockerTools`) image profile — deterministic by construction |

## 0. Prerequisites (operator host)

- A container engine — `podman` (preferred, rootless + reproducible) or `docker`.
  *(Nix path instead: a Nix host with `dockerTools`.)*
- Registry credentials for the registry you will push to (operator-held).
- A deployment target (host with the engine, an orchestrator, or a NixOS host).
- The **verified cloud artifact** to package. Verify it first with
  [`../../deployment/signing/verify-build.sh`](../../deployment/signing/verify-build.sh),
  or build it from source (strongest verification). Then wire it into the
  `COPY`/`ENTRYPOINT` placeholders in the `Containerfile` (or supply
  `posternCloud` to `cloud-image.nix`).

## 1. Build the image (local only)

`build-image.sh` sets the reproducibility knobs and **only builds** — it never
pushes and never deploys.

```sh
# Pin the base by a digest YOU vetted. -n does a dry-run (prints the command).
./build-image.sh -d sha256:<vetted-base-digest> -t postern-cloud:local -n
./build-image.sh -d sha256:<vetted-base-digest> -t postern-cloud:local
```

Equivalent manual build:

```sh
podman build \
  --build-arg BASE_DIGEST=sha256:<vetted-base-digest> \
  --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct 2>/dev/null || echo 0)" \
  -t postern-cloud:local -f Containerfile .
```

**Nix alternative** (deterministic by construction, on a Nix host):

```sh
nix-build cloud-image.nix -A image      # ./result is an OCI tarball
podman load < result
```

## 2. Check reproducibility yourself (recommended, honest)

```sh
./build-image.sh -d sha256:<same-digest> -t postern-cloud:rebuild
podman image inspect postern-cloud:local   --format '{{.Id}}'
podman image inspect postern-cloud:rebuild --format '{{.Id}}'
# Same inputs should yield the same image id. If not, investigate embedded
# timestamps/paths/ordering. Do NOT call it "reproduced" until an independent
# party matches the bytes — until then it is "reproducible-by-design".
```

## 3. Push the image (separate, explicit step)

Building never pushes. Tag with a version and push by digest.

```sh
podman login registry.example.com
podman tag postern-cloud:local registry.example.com/postern-cloud:1.0.0
podman push registry.example.com/postern-cloud:1.0.0

# Record the digest and deploy BY DIGEST (immutable), not by the moving tag:
podman inspect --format '{{index .RepoDigests 0}}' \
  registry.example.com/postern-cloud:1.0.0
# -> registry.example.com/postern-cloud@sha256:<digest>
```

Optionally sign the pushed image with your registry's supply-chain tooling
(e.g. `cosign sign`) on top of the checksum+minisign channel in
[`../../deployment/signing/`](../../deployment/signing/), so consumers can verify
provenance.

## 4. Deploy the image (separate, explicit step)

Deploy the **pinned digest** from step 3. Provide config/secrets at runtime —
never bake them into the image, never commit them.

```sh
# Point compose.yaml's `image:` at the pinned digest, then:
mkdir -p ./config              # operator-owned, read-only-mounted config
# put runtime secrets in an operator-managed source (secrets manager / env_file),
# referenced by compose.yaml — never committed.
podman compose up -d           # or: docker compose up -d
```

The stack manifest defaults to: **non-root** (uid 10001), **read-only root FS**,
**all capabilities dropped**, **no-new-privileges**, **egress-controlled**
(deny-by-default network), **telemetry off**, port bound to `127.0.0.1`.

## 5. Front it, persist data, control egress

- **TLS + authn/z:** terminate at your own reverse proxy; the container binds
  loopback and expects a trusted proxy in front. Never expose the container port
  raw to the internet.
- **Data:** persists in the `postern-data` volume. Back it up per your policy.
- **Egress:** default is closed. If the service genuinely needs outbound access,
  attach the explicit `egress` network in `compose.yaml`, restrict it to an
  allow-list, and **document exactly what it reaches and why**.

## 6. Operate

- Watch health (`healthcheck` in `compose.yaml`; replace the stub with a real
  check) and your reverse proxy's logs.
- Roll forward by pushing a new digest and redeploying; keep the previous digest
  for rollback.
- Stand up support/SLA with the scaffold in
  [`../../deployment/support/`](../../deployment/support/).

## Editions & privacy recap

- **Personal / community:** free, buildable from source. Never called "Postern OS".
- **Self-hosted (enterprise):** most private of the served editions — you hold
  the infrastructure. See [`../../deployment/`](../../deployment/).
- **Cloud (this edition):** managed/hosted convenience; **less private —
  disclosed**. Paid work is the licence + SLA support billed in **fiat**. The
  token is never the product or the price.
