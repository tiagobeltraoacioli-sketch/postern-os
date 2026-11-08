<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Signed / notarized enterprise-build channel

This directory is the **signing pipeline** for Postern Enterprise deliveries. It
reuses the project's existing signing convention by reference — a
`minisign`-signed `SHA256SUMS` manifest, exactly as the OS and postmarketOS
images use (see `../../../pmos-overlay/FLASH.md` and
`../../../pmos-overlay/publish-to-r2.sh`). One convention, verified the same way
everywhere.

## What a signature here proves — and what it does not

A valid signature proves the delivery **came from the holder of the enterprise
signing key** and is **byte-identical** to what was signed. It does **not**
prove the binaries match any source, and it is **not** attestation, **not** an
audit, and **not** a claim the software is secure or production-ready.
**Reproducible-by-design is not reproduced.** Building from source stays the
strongest verification.

## Keys — operator-run, never committed

The real enterprise signing key is **operator-held** and lives **outside this
repository**. Nothing here embeds it.

`keys/dev-sample.pub` is a **DEV / SAMPLE** key generated only so the flow can be
exercised end-to-end. See `keys/dev-sample.pub.README`. **Never** sign a real
delivery with it and **never** present its output as authentic. Both scripts
print a loud warning when they touch a `dev-sample` key.

## Producing a signed delivery (operator side)

```sh
# 1. Stage the verified artifacts in a directory, e.g. ./dist/
# 2. Sign: writes dist/SHA256SUMS and dist/SHA256SUMS.minisig
./sign-build.sh -a ./dist -s /path/to/OPERATOR-secret.key -t postern-enterprise-v1

# Unattended (operator CI): pass the key password via env instead of a prompt.
MINISIGN_PASSWORD=… ./sign-build.sh -a ./dist -s /path/to/OPERATOR-secret.key
```

Deliver the artifacts **together with** `SHA256SUMS` and `SHA256SUMS.minisig`.

### On "notarized"

"Notarized" (Apple notarization, Windows Authenticode, etc.) is a **platform-
specific** extra step layered on top of this checksum+signature channel — it is
operator-run with the platform's own credentials and tooling, which are **not**
included or exercised here. This pipeline is the portable, platform-agnostic
floor: checksums + a detached minisign signature every customer can verify with
one open-source tool. Document any platform notarization you add alongside it.

## Verifying a delivery (customer side)

Verify **in order** — signature first (authenticates the manifest), then
checksums (authenticate the bytes):

```sh
# Against the real published enterprise key string:
./verify-build.sh -d ./delivery -P RWS…realkey…

# Or against a pinned key file:
./verify-build.sh -d ./delivery -p keys/postern-enterprise.pub
```

Exit `0` = verified. Anything else = **stop, do not use the delivery.**

## End-to-end self-test (with the DEV/SAMPLE key)

```sh
mkdir -p /tmp/pe-demo && echo "hello enterprise" > /tmp/pe-demo/artifact.bin
./sign-build.sh   -a /tmp/pe-demo -s keys/dev-sample.key -t demo
./verify-build.sh -d /tmp/pe-demo -p keys/dev-sample.pub
```

This proves the **flow**, not the authenticity of any real Postern delivery.
