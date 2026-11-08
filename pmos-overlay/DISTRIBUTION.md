# Distribution — hosting the signed apk repository on Cloudflare R2

How "Postern for postmarketOS — community edition" packages reach users:
a plain static apk repository in a public Cloudflare R2 bucket behind a
custom domain, published by `publish-to-r2.sh`. Design follows the advisor
docs `pmos-01-packaging.md` (§5) and `pmos-07-distribution-updates.md`.

**Read `HONESTY.md` first.** Everything in this repository is *signed only*:
not reproducible, not attested, never called "Postern OS". The disclosure
copy at the bottom of this file must render on the repo index page and on
the install page, above the fold, not behind a link.

## Bucket layout

One branch directory per supported pmOS release (a branch = one Alpine ABI;
`v26.06` = Alpine 3.24), plus `edge`, with per-arch subdirectories beneath —
mirroring postmarketOS's own mirror shape:

```
<R2 bucket>  →  https://apk.posternlabs.com/        # TODO: real custom domain
├── keys/
│   └── packages@posternlabs.com-<8hex>.rsa.pub     # stable URL; write-once
├── v26.06/                                         # pmOS v26.06 = Alpine 3.24 ABI
│   ├── aarch64/
│   │   ├── APKINDEX.tar.gz                         # signed by abuild-sign
│   │   └── *.apk                                   # individually signed, immutable
│   └── x86_64/
│       ├── APKINDEX.tar.gz
│       └── *.apk
├── edge/                                           # tracks pmOS master / Alpine edge
│   └── <same shape>
└── meta/
    ├── v26.06.json                                 # publish pointer, written LAST
    └── edge.json
```

Layout rules:

- **The `/etc/apk/repositories` line stops at the branch.** apk appends
  `<arch>/APKINDEX.tar.gz` to the configured URL itself (Alpine user
  handbook; advisor pmos-01 §5.3) — so the repo line is
  `@postern https://apk.posternlabs.com/v26.06`, never `.../v26.06/aarch64`.
- **noarch packages live duplicated in every arch dir**, per Alpine
  convention: abuild emits noarch apks into the arch directory being built
  and indexes them in that arch's `APKINDEX.tar.gz`. There is no shared
  noarch directory (none exists in apk's URL scheme).
- **One ABI per branch dir.** Packages built against Alpine 3.24 are
  published under `v26.06` only. A new pmOS release gets a new branch dir;
  until it exists, users on the new release get a 404 on the index — apk
  fails safe rather than serving wrong-ABI packages.
- **`keys/` is write-once.** The public key's filename is load-bearing
  (apk resolves the `.SIGN.RSA.<filename>` signature name against
  `/etc/apk/keys/<filename>`), so it is published under its original
  `abuild-keygen` name and never renamed or replaced. Key rotation = a new
  filename shipped ahead of time via the `postern-repo-keys` package, then a
  signing switch — never an overwrite of an existing `keys/` object.
- **`meta/<branch>.json`** is for our site/monitoring only (publish
  timestamp, per-arch index sha256, key fingerprint). apk never reads it.

## Publishing: `publish-apk-repo.sh`

> **Note:** the apk-repo publisher is **`publish-apk-repo.sh`** (System A —
> signed apks + `APKINDEX`). The similarly named `publish-to-r2.sh` in this
> directory is a **different** tool — it publishes the whole-disk `.img`
> (System B, `-i/-m/-s`; see `../FLASH.md`, `../aarch64-build.md`). Do not
> confuse the two. Both are documented against the same R2 layout and honesty
> rails; `../KEYS.md` §1 explains the two signing systems.

Uploads go through `build/r2_upload.py` against R2's S3-compatible endpoint
`https://<ACCOUNT_ID>.r2.cloudflarestorage.com`, per Cloudflare's docs
(S3 API compatibility: developers.cloudflare.com/r2/api/s3/api/; aws/boto3
usage incl. region `auto` and the checksum-trailer workaround:
developers.cloudflare.com/r2/examples/aws/aws-cli/; credentials come from an
R2 API token: developers.cloudflare.com/r2/api/tokens/).

`publish-apk-repo.sh` enforces the hardening this document specifies (see
`../REPO-HARDENING.md` §3): the `APKINDEX.tar.gz` must be **signed with a member
named for the `-k` pubkey** (or it refuses to publish), `keys/<name>` is
**write-once**, existing `*.apk` objects are **immutable** (a size change aborts
the publish — bump `pkgrel`), a `SHA256SUMS.txt` audit sidecar is written per
arch, and uploads follow the fail-safe order below.

Credentials and endpoint come from the **environment only** — nothing is
hardcoded in the script:

| Variable | Required | Meaning |
|---|---|---|
| `AWS_ACCESS_KEY_ID` | yes | R2 API token — Access Key ID |
| `AWS_SECRET_ACCESS_KEY` | yes | R2 API token — Secret Access Key |
| `R2_BUCKET` | yes | target bucket name |
| `R2_ACCOUNT_ID` | one of these two | endpoint derived as `https://$R2_ACCOUNT_ID.r2.cloudflarestorage.com` |
| `R2_ENDPOINT_URL` | one of these two | full endpoint URL (overrides `R2_ACCOUNT_ID`) |
| `R2_PUBLIC_BASE_URL` | no | public domain base (e.g. `https://apk.posternlabs.com`); only used to print the install snippet |

Usage (point `-r` at the abuild output tree, `~/packages/<repo>/`, which holds
the per-arch `*.apk` + signed `APKINDEX.tar.gz`):

```sh
# dry run — no credentials, no network (validates signatures, hashes, plan):
./publish-apk-repo.sh -b v26.06 -r ~/packages/postern \
    -k ~/.abuild/packages@posternlabs.com-<8hex>.rsa.pub -n

# real publish (env vars set from the CI secret store):
./publish-apk-repo.sh -b v26.06 -r ~/packages/postern \
    -k ~/.abuild/packages@posternlabs.com-<8hex>.rsa.pub
```

Generate/rotate the `-k` signing key with `keys/postern-keygen.sh` (`../KEYS.md`).

### Fail-safe ordering

Clients only see a package once the *signed index* lists it, so the index
upload is the atomic-enough client-visible flip (advisor pmos-01 §5.2):

1. **Public key** → `keys/` (write-once; skipped if already identical,
   hard error if a different file exists under the same name).
2. **All `*.apk` files** → `<branch>/<arch>/` (invisible to clients until
   step 3; immutable — an existing object with a different size aborts the
   publish: bump `pkgrel`, never republish a changed file under the same
   `pkgver-pkgrel`).
3. **`APKINDEX.tar.gz` per arch** — the flip. Preflight refuses any index
   that lacks a `.SIGN.RSA.*` member or whose signature key name doesn't
   match the `-k` public key.
4. **`meta/<branch>.json`** — the operator pointer, written dead last, so
   its presence/timestamp proves the whole publish completed.

A publish that dies at any step leaves clients on the previous consistent
index. Re-running is idempotent: existing apks and the key are
verified-and-skipped; only index + pointer are re-uploaded.

### Caching

Set as object `Cache-Control` metadata (R2 serves it on public/custom
domains): `*.apk` → `max-age=31536000, immutable`; `APKINDEX.tar.gz` and
`meta/*.json` → `max-age=60` (they change every publish); the key →
`max-age=3600`. With a 60 s index TTL no cache purge is needed; if the
domain sits behind Cloudflare's CDN cache, an optional post-publish purge of
`*/APKINDEX.tar.gz` tightens that window.

## Installing (end user, on a pmOS v26.06 device)

This snippet goes verbatim (with the real domain and key name) on the
install page, together with the disclosure below and the key fingerprint
published out-of-band (website, git repo, release announcements):

```sh
# 1. Trust the Postern signing key (keep the filename exactly as published)
wget -P /etc/apk/keys https://apk.posternlabs.com/keys/packages@posternlabs.com-<8hex>.rsa.pub

#    Check its fingerprint against the ones we publish out-of-band:
sha256sum /etc/apk/keys/packages@posternlabs.com-*.rsa.pub

# 2. Add the TAGGED repository for your pmOS release
#    (the line stops at the branch — apk appends <arch>/ itself)
echo "@postern https://apk.posternlabs.com/v26.06" >> /etc/apk/repositories

# 3. Install
apk update
apk add postern@postern
```

- **Never `--allow-untrusted`** — not in docs, not in support answers, not
  as a bootstrap. If verification fails, something is wrong; forcing past it
  is the one reflex we must not teach.
- **The repo is tagged (`@postern`)** so apk only consults it for packages
  explicitly pinned `@postern`: even a compromised Postern repo can never
  satisfy a dependency of a base pmOS/Alpine package (repository pinning,
  Alpine Package Keeper wiki).
- **Honest bootstrap framing:** step 1 trusts our TLS certificate; every
  install and update after it is verified against the key just pinned.
- **Updates ride `apk upgrade`** — no self-updater, no phoning home. We
  cannot push updates; a user who never runs `apk upgrade` never gets fixes.

## What you can verify here (and what you can't) — mandatory disclosure

> **EN — What you can verify here (and what you can't).**
> Packages in this repository are cryptographically signed by us. Your package
> manager checks that signature on every install and update — that proves the
> package came from Postern and wasn't tampered with in transit.
> What it does **not** prove: that the binary matches the source code.
> postmarketOS is built on Alpine Linux, which is not bit-for-bit reproducible, so
> **nobody — including us — can rebuild these packages and get an identical file.**
> Our build scripts are public and you can rebuild from source yourself, but you'll
> get a functionally equivalent file, not an identical one, and this repository
> cannot attest the rest of your system at all.
> If reproducible, attestable builds are what you need, that is exactly what
> [Postern OS (Nix images)](link) provides, on a shorter list of devices.

> **PT — O que você pode verificar aqui (e o que não pode).**
> Os pacotes deste repositório são assinados criptograficamente por nós. Seu
> gerenciador de pacotes confere essa assinatura em toda instalação e atualização —
> isso prova que o pacote veio do Postern e não foi adulterado no caminho.
> O que isso **não** prova: que o binário corresponde ao código-fonte.
> O postmarketOS é construído sobre o Alpine Linux, que não é reprodutível
> bit-a-bit; portanto **ninguém — nem nós — consegue recompilar estes pacotes e
> obter um arquivo idêntico.** Nossos scripts de build são públicos e você pode
> compilar do fonte, mas obterá um arquivo funcionalmente equivalente, não
> idêntico — e este repositório não atesta o restante do seu sistema.
> Se builds reprodutíveis e atestáveis são o que você precisa, é exatamente isso
> que o [Postern OS (imagens Nix)](link) oferece, numa lista menor de aparelhos.

Per `HONESTY.md`: nothing in this overlay has been built or device-tested
yet — do not publish a live repo (or this page) until a real `abuild` run
and hardware smoke test exist, and say so with zero-count honesty.

## Sources

- Cloudflare R2 — S3 API compatibility & endpoint shape:
  https://developers.cloudflare.com/r2/api/s3/api/
- Cloudflare R2 — aws CLI usage (endpoint-url, region `auto`, CLI v2.23+
  checksum settings): https://developers.cloudflare.com/r2/examples/aws/aws-cli/
- Cloudflare R2 — API tokens (S3 Access Key ID / Secret Access Key):
  https://developers.cloudflare.com/r2/api/tokens/
- Alpine apk spec (index/package signatures, key lookup by filename):
  https://wiki.alpinelinux.org/wiki/Apk_spec
- Alpine Package Keeper (repository pinning / tagged repos):
  https://wiki.alpinelinux.org/wiki/Alpine_Package_Keeper
- Advisor docs: `pmos-01-packaging.md` §5 (layout, R2, publish order,
  caching), `pmos-07-distribution-updates.md` (install path, tagged repo,
  disclosure copy, rotation).
