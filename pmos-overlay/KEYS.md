# KEYS — signing keys, the alpha→stable path, and rotation

**Read `HONESTY.md` and `PUBLISHED.md` first.** This is *Postern for
postmarketOS — community edition*, never "Postern OS". Signatures here prove
**who published** an artifact and that it arrived unmodified — they prove
**nothing** about reproducibility or attestation (Alpine/pmOS is not
bit-reproducible; there is no Nix closure and no hardware anchor). The coin is
worthless by design and none of this is a security/financial/legal claim.

This file is the single source of truth for the Postern-for-pmOS signing keys:
what exists today, the honest gap, the documented path from the **alpha build
key** to a **stable long-lived release key**, how rotation works, and where the
public keys are published (in **≥2 independent places**). The helper that
generates and rotates keys is `keys/postern-keygen.sh` — **no private key is
generated or committed in this repository**; that script is run by a human on a
trusted, offline-capable host.

---

## 1. Two independent signing systems (do not conflate them)

There are two artifacts and two signature schemes. They use **different tools,
different keys, and different verification commands.**

| # | Artifact | Signs what | Tool | Key type | Client verifies with |
|---|---|---|---|---|---|
| **A** | apk repository | each `*.apk` + `APKINDEX.tar.gz` | `abuild-sign` / `apk` | RSA (openssl) | `apk` against `/etc/apk/keys/<name>` |
| **B** | disk image | `SHA256SUMS` over the `.img` files | `minisign` | Ed25519 (minisign) | `minisign -Vm SHA256SUMS -P <pubkey>` |

- **System A** is the one that matters for `apk add postern` (`DISTRIBUTION.md`,
  `PUBLISHED.md`). The **public key's filename is load-bearing**: `apk` looks up
  the signature `.SIGN.RSA.<filename>` against `/etc/apk/keys/<filename>`, so the
  pubkey is published under its exact `keygen` name and is **write-once** — never
  renamed, never overwritten (see rotation below).
- **System B** is the one that matters for the whole-disk `.img`
  (`publish-to-r2.sh`, `FLASH.md`). minisign identifies a key by the pubkey
  string itself plus an 8-byte key id embedded in every signature.

---

## 2. What exists today — honest status

### System A (apk repo) — **ALPHA BUILD KEY**

- Key name: **`builder-6a52d247.rsa.pub`**
- Published at: `…/pmos/keys/builder-6a52d247.rsa.pub` (one R2 location today).
- This is an **alpha build key**, not a stable, published release key. Treat any
  signature under it as **"this build, this key"** — not a durable trust anchor.
- **Gap:** it is published in only **one** place, was generated ad hoc on the
  build host, and has no documented rotation. Adopting a stable release key with
  a rotation policy and ≥2 publish locations is a **prerequisite** before this
  repo is recommended broadly (`PUBLISHED.md`, "Next to earn each claim" #3).

### System B (image) — **ALPHA/BUILD minisign KEY**

- Public key string:
  `RWTSe98wfKKHuVRDnywuQmH/cMyP/HNuD/hFFLQeKdQeAHENliqJpmKs`
- Embedded as the default expected pubkey in `publish-to-r2.sh` and printed in
  `FLASH.md`/`aarch64-build.md` for user-side verification.
- Same honesty caveat: it authenticates the publisher, nothing more, and it is
  not yet governed by the rotation policy below.

> **No image has ever been built or booted** (`HONESTY.md`, `PUBLISHED.md`), so
> System B has never actually signed a shipped image. Built ≠ booted; signed ≠
> reproducible ≠ attested.

---

## 3. The stable release key — target state

A **stable release key** is a long-lived key, generated deliberately, kept
offline, published in ≥2 independent places with out-of-band fingerprints, and
governed by the rotation policy in §5. The alpha keys above are retired to
"build/testing only" once the stable keys exist.

### System A — stable apk repo key

- Canonical name (per `DISTRIBUTION.md`): **`packages@posternlabs.com-<8hex>.rsa.pub`**
  where `<8hex>` is the hex suffix `abuild-keygen`/`postern-keygen.sh` assigns.
  The `packages@posternlabs.com` prefix ties the key to a role address, not a
  person, so it survives maintainer changes.
- 4096-bit RSA (matches Alpine/abuild convention; `abuild-sign` uses openssl RSA).
- The private half **never leaves** the signing host or the CI secret store; it
  is backed up offline (paper/HSM/encrypted removable), because losing it means
  re-keying every installed client.

### System B — stable image key

- A fresh `minisign` keypair generated with a passphrase; the secret key lives in
  the CI secret store (or offline) and is referenced by `publish-to-r2.sh -s`.
- Its pubkey string replaces the alpha string in `publish-to-r2.sh`'s
  `DEFAULT_PUBKEY` and in `FLASH.md`/`aarch64-build.md` at cutover.

### Cutover from alpha → stable (both systems)

1. Generate the stable keypair with `keys/postern-keygen.sh` (see §4) on a
   trusted host. **Do not** reuse the alpha key material.
2. Publish the **stable public key** to all ≥2 locations in §6, with fingerprints
   out-of-band, **before** signing anything with it (System A ships the new
   pubkey ahead of the signing switch — see §5).
3. Re-sign the current artifacts with the stable key:
   - System A: rebuild/re-index the apk repo and `abuild-sign` the `APKINDEX`
     with the stable key (`publish-apk-repo.sh`).
   - System B: re-run `publish-to-r2.sh` with the stable minisign secret key
     (the script self-checks the signature against the published pubkey and
     refuses a mismatch).
4. Update `PUBLISHED.md` to record the stable key names + fingerprints and to
   flip the "alpha build key" caveat to "stable release key, rotation documented
   in KEYS.md". Keep the built≠booted and non-attestable rails intact.
5. Keep the alpha key trusted **only** for verifying already-shipped alpha
   artifacts; never sign new release artifacts with it.

---

## 4. Generating / rotating keys — `keys/postern-keygen.sh`

The helper does **only** local key material; it never uploads and never touches
this git tree. It refuses to overwrite an existing key (no silent clobber of a
private key) and prints the exact publish + fingerprint checklist afterward.

```sh
# System A — stable apk repo RSA key (openssl; abuild-sign compatible):
keys/postern-keygen.sh apk   --email packages@posternlabs.com --out ~/.abuild

# System B — image minisign key (prompts for a passphrase):
keys/postern-keygen.sh image --out ~/.minisign/postern-image

# Rotation prints the ship-new-key-first / switch-signing-second procedure:
keys/postern-keygen.sh rotate-apk   --email packages@posternlabs.com --out ~/.abuild
keys/postern-keygen.sh rotate-image --out ~/.minisign/postern-image
```

**No key produced by this script is committed.** `.rsa`, `.key`, and minisign
secret files must stay out of git (add them to your global gitignore / never
`git add` them). Only **public** keys and their **fingerprints** are ever
published, and those go to R2 + the locations in §6 — not necessarily into this
repo (a fingerprint table here is fine; a raw pubkey blob is optional).

---

## 5. Rotation policy

Rotation must never present a window where a client cannot verify a legitimately
published artifact, and must never overwrite a key file that clients already
trust by name.

### System A (apk) — ship-new-key-first, then switch signing

`apk` resolves signatures by the pubkey **filename**, and `keys/` objects are
**write-once**, so you cannot "replace" a key in place. Instead:

1. **Distribute** the new pubkey ahead of time. Ship it as a file in a
   `postern-repo-keys` package (or push it to every location in §6) and give
   users time to `apk upgrade` so `/etc/apk/keys/<new>` is present **before** any
   package is signed with the new key.
2. **Switch signing.** Start signing `APKINDEX` with the new key
   (`publish-apk-repo.sh -k <new>.rsa.pub`). Clients that already have the new
   pubkey verify seamlessly; clients that don't yet fail **safe** (they refuse
   the index) rather than trusting blindly. Never teach `--allow-untrusted`.
3. **Retire** the old key after a published deprecation window: stop signing with
   it, keep its pubkey served (do not delete `keys/<old>`) so historical
   artifacts still verify, and remove it from the shipped key set in a later
   `postern-repo-keys` bump.
4. **Compromise** (private key leaked): sign a dated revocation notice with any
   still-trusted key, publish it to all §6 locations, roll to a new key
   immediately, and bump `pkgrel` of everything re-signed. There is no CRL in
   apk — revocation is out-of-band + a fast key roll.

### System B (image) — publish-new-pubkey-first, transition statement

1. Generate the new minisign keypair; publish the **new pubkey** to all §6
   locations with its fingerprint.
2. Sign a short **transition statement** (`"the Postern image key rotates from
   <old id> to <new id> on <date>"`) with the **old** secret key and publish it,
   so holders of the old key can trust the announcement of the new one.
3. Update `publish-to-r2.sh` `DEFAULT_PUBKEY` + `FLASH.md`/`aarch64-build.md` to
   the new pubkey string; re-sign the current `SHA256SUMS` with the new key.
4. Keep the old pubkey documented for verifying already-shipped images.

---

## 6. Publish the public key in ≥2 independent places (required)

A single publish location is a single point of failure and a single point of
tampering. Every **public** key (both systems) is published in **at least two
independent locations**, each carrying the **same fingerprint** so a user can
cross-check:

1. **R2 object storage** — the canonical machine-fetchable copy:
   - System A: `…/pmos/keys/<name>.rsa.pub` (write-once).
   - System B: the pubkey string is in `SHA256SUMS.minisig`'s trust chain and
     printed on the download page.
2. **Git repository** — this `KEYS.md` fingerprint table (below) is version
   controlled and diff-auditable; a change to a fingerprint is a visible commit.
3. **Website** — `posternlabs.com` install/download page, above the fold, next
   to the mandatory `HONESTY.md` disclosure.
4. **Release announcements** — each tagged release note restates the current key
   names + fingerprints.

Publishing to R2 **and** git (1 + 2) already satisfies "≥2 independent places";
website + announcements are the recommended additional anchors. The fingerprints
must be **identical** across all of them.

### Fingerprint table (fill at cutover — do NOT invent values)

Compute with the commands shown; paste the real output here when the stable keys
are generated. Left as placeholders because **no stable key has been generated**
(and none is committed):

| System | Key name / id | Fingerprint | Status |
|---|---|---|---|
| A (apk) | `builder-6a52d247.rsa.pub` | `sha256sum <file>` → _TODO: paste_ | **alpha build key** (current) |
| A (apk) | `packages@posternlabs.com-<8hex>.rsa.pub` | `sha256sum <file>` → _TODO_ | stable (not yet generated) |
| B (image) | `RWTSe98wfKKHuVRDnywuQmH/cMyP/HNuD/hFFLQeKdQeAHENliqJpmKs` | minisign pubkey string is its own id | **alpha/build key** (current) |
| B (image) | stable minisign pubkey | _TODO_ | stable (not yet generated) |

```sh
# System A fingerprint (what users cross-check):
sha256sum /etc/apk/keys/packages@posternlabs.com-<8hex>.rsa.pub

# System B: the pubkey string in minisign's .pub file IS the identity;
# the 8-byte key id is shown by:
minisign -V -m SHA256SUMS -x SHA256SUMS.minisig -P <pubkey>   # prints the key id it used
```

---

## 7. Do / don't

- **Do** keep private keys off this repo and out of git, always.
- **Do** publish every public key in ≥2 places with matching fingerprints.
- **Do** ship a new apk pubkey **before** signing with it; keep old pubkeys
  served so historical artifacts verify.
- **Don't** overwrite or rename a `keys/<name>` object — the filename is
  load-bearing for `apk`.
- **Don't** ever recommend `--allow-untrusted`, not even to bootstrap.
- **Don't** describe any of these signatures as reproducibility or attestation,
  and don't let the "Postern OS" name touch this tier.
