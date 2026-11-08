<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# `config/` — operator-owned runtime config mount (NOT baked into the image)

`compose.yaml` mounts this directory **read-only** at `/etc/postern`. It is for
operator-provided, runtime-injected configuration ONLY. It is deliberately kept
out of the image build context (see `.dockerignore`).

**Never commit secrets here.** The mandatory `VENDOR_PUBLIC_KEY` and any admin
token are injected at runtime as environment / secrets (a secrets manager,
`env_file`, or `flyctl secrets set`), never baked into the image and never
checked in. The service is fail-closed: with no `VENDOR_PUBLIC_KEY` it refuses to
start rather than run fail-open.
