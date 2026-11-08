<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Deployment packaging — self-hosting the Postern Enterprise edition

Two interchangeable, **reproducible-by-design** skeletons for self-hosting the
enterprise edition:

| Skeleton | File | Use when |
|---|---|---|
| Container | [`Containerfile`](Containerfile) + [`compose.yaml`](compose.yaml) | podman/docker hosts; quickest path |
| Nix profile | [`enterprise-profile.nix`](enterprise-profile.nix) | NixOS hosts; strongest determinism; mirrors the repo's `os/*.nix` |

> **Reproducible-by-design ≠ reproduced.** Both are written to rebuild
> deterministically (pinned base digest / pinned inputs, `SOURCE_DATE_EPOCH`,
> egress-closed assembly). **No independent bit-for-bit reproduction has been
> performed or attested here.** "Reproducible" is a property you can *check*
> (`nix build --rebuild`, `diffoscope`, a rebuild + `sha256sum` compare), not
> one this repo has discharged for you. Nothing here is hardened, audited, or
> production-ready.

## Privacy posture (default, by construction)

- **No telemetry, no analytics, no phone-home** (`POSTERN_TELEMETRY=off`).
- **Egress-closed by default** — declare any outbound need explicitly.
- **Secrets injected at runtime**, never baked into an image or committed.
- **Non-root, least-privilege** (dropped capabilities, read-only root FS in the
  container; systemd sandboxing in the Nix profile).

## Container flow (operator-run)

```sh
# 1. Verify the artifact you are about to package (signing channel):
../signing/verify-build.sh -d ./dist -P RWS…realkey…

# 2. Put the verified artifact where the Containerfile expects it, then build
#    with a pinned base digest and a fixed timestamp:
podman build \
  --build-arg BASE_DIGEST=sha256:<vetted-base-digest> \
  --build-arg SOURCE_DATE_EPOCH="$(git -C ../../.. log -1 --format=%ct 2>/dev/null || echo 0)" \
  -t postern-enterprise:local -f Containerfile .

# 3. Run:
podman compose up -d      # or: docker compose up -d
```

The `ENTRYPOINT` and `COPY` lines are **placeholders** — wire in your real
service binary. The default entrypoint intentionally exits with a reminder.

## Nix flow (operator-run, on a Nix host)

`enterprise-profile.nix` is a NixOS module exposing
`services.postern-enterprise`. It was **written on a non-Nix host and is not
built here** (same caveat as `os/cloud.nix`). Supply `package` (built from
source, or verified via the signing channel) and enable the service:

```nix
services.postern-enterprise = {
  enable = true;
  package = self.packages.${system}.postern-enterprise;  # your artifact
  port = 8080;
  # telemetry stays false by construction
};
```

## Checking reproducibility yourself

1. Build the artifact twice from the same pinned inputs.
2. Compare: `sha256sum` the two outputs, or run `diffoscope` on them.
3. If they differ, the build is not yet reproducible — investigate timestamps,
   embedded paths, and non-deterministic ordering. Report parity results
   honestly; do not label a build "reproduced" until an independent party has
   matched the bytes.
