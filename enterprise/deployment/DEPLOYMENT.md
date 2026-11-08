<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# DEPLOYMENT.md — self-hosting Postern Enterprise, end to end

This is the operator runbook that ties the three pieces together: **verify a
signed build → package it → run it**, with SLA support alongside. Everything
requiring real infrastructure or keys is **operator-run**; nothing in this
document is executed or attested by the repository.

> **Standing caveats.** Not secure, audited, attested, or production-ready.
> **Reproducible-by-design is not reproduced.** A signature proves origin and
> integrity, not source-correspondence or attestation. The coin is not a
> security; licences and support are billed in fiat.

## 0. Prerequisites (operator host)

- `minisign` (sign/verify), `sha256sum`/`shasum`, `jq`.
- A container engine (`podman` or `docker`) **or** a NixOS host.
- The **published enterprise public key** (string or pinned file). The private
  signing key is operator-held and never lives in this repo.

## 1. Receive & verify the build

A delivery is a directory of artifacts plus `SHA256SUMS` and
`SHA256SUMS.minisig`. Verify **before** doing anything else:

```sh
signing/verify-build.sh -d ./delivery -P RWS…realkey…
# exit 0 => verified; anything else => STOP, discard the delivery.
```

Verification order is fixed: the signature authenticates `SHA256SUMS`, and
`SHA256SUMS` authenticates each artifact. See
[`signing/SIGNING.md`](signing/SIGNING.md). Building from source remains the
strongest verification and is always available for the free build.

## 2. Package for self-hosting

Pick one skeleton (both are **reproducible-by-design, not reproduced** — see
[`packaging/PACKAGING.md`](packaging/PACKAGING.md)):

**Container (podman/docker):**

```sh
cd packaging
podman build \
  --build-arg BASE_DIGEST=sha256:<vetted-base-digest> \
  --build-arg SOURCE_DATE_EPOCH="$(git -C ../.. log -1 --format=%ct 2>/dev/null || echo 0)" \
  -t postern-enterprise:local -f Containerfile .
podman compose up -d
```

**NixOS profile:** enable `services.postern-enterprise` from
[`packaging/enterprise-profile.nix`](packaging/enterprise-profile.nix) with your
verified `package`. (Written on a non-Nix host; build it on a Nix host.)

Both default to: **no telemetry**, **egress-closed**, **non-root**,
**least-privilege**, **secrets injected at runtime** (never committed).

## 3. Front it and persist data

- Terminate TLS with your own reverse proxy; the container binds `127.0.0.1`
  by default.
- Data persists in the `postern-data` volume (container) or `StateDirectory`
  (Nix). Back it up per your own policy.

## 4. Optional: platform notarization

If you distribute platform-native artifacts, add Apple notarization / Windows
Authenticode **on top of** the checksum+signature channel, using the platform's
own credentials and tooling (operator-run, not included here). Document it
beside the minisign channel so customers can verify both.

## 5. Stand up support / SLA

- Track entitlements and response targets with the scaffold in
  [`support/`](support/); read [`SLA.md`](SLA.md) for the model.
- Intake is minimal-data and privacy-preserving; no telemetry backs it.

## 6. Verify your own reproducibility (recommended, honest)

Rebuild the artifact from the same pinned inputs and compare bytes
(`sha256sum` / `diffoscope`). Only call a build "reproduced" once an
independent party matches the bytes — until then it is "reproducible-by-design".

## Editions & pricing recap

- **Personal / community:** free, buildable from source. Not "Postern OS".
- **Business:** free **6-month** evaluation, then a paid **fiat** licence.
- **Enterprise:** paid **fiat** licence with priority/SLA support.
- **Support/SLA is the paid work.** The token is never the product or the price.
