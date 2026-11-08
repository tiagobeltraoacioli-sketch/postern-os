# Curating the Postern Store — how to add an app

The Postern Store is a **third-party app distribution catalog**, not a walled
app store. The catalog is one signed index file, [`catalog.json`](catalog.json)
(schema `postern.catalog/v1`). `index.html` renders from it: a copy is embedded
in the page so it works offline / under CSP / from `file://`, and a newer
`catalog.json` on the same origin is pulled opportunistically at boot.

**Read `../../pmos-overlay/HONESTY.md` first.** The honesty spine below is not a
style guide — parts of it are enforced in code (`normalizeEntry` in
`index.html`), so a dishonest entry is downgraded, not trusted.

## The honesty spine (non-negotiable)

1. **A proprietary app can only ever be linked or proxied — never hosted.**
   If `license.class` is `proprietary` (or `license.foss` is false), the loader
   forces `distribution.hosted_by_us = false`, coerces the model to `link`, and
   drops any advertised `artifact`. You cannot list a closed-source app as
   "hosted by us" no matter what you write in the JSON.
2. **The `attestable` badge is reserved for `tier: attestable-nix`** — apps
   built from source inside the reproducible Postern OS Nix closure. On any
   other tier the loader strips the `attestable` security tag. A signed apk is
   *signed*, not *attestable*.
3. **Never imply a signature or checksum you don't have.** Hosted entries carry
   `signing.state`; unless it is `"published"` the app renders as
   "· unpublished" and its checksum is treated as null. This scaffold ships
   everything `unpublished` because nothing has been built yet. At the
   **catalog level**, the Store is now a *verifying* client: it checks a
   detached Ed25519 signature over `catalog.json` in-page and shows an honest
   trust banner (**UNSIGNED / VERIFIED / TAMPERED / UNVERIFIED**). Nothing is
   signed yet, so the live state is **UNSIGNED** — see
   [`SIGNING.md`](SIGNING.md) for the scheme and how to publish a signed release
   (it explains the `index_signature` field below).
4. **Every app shows its tier, license, and worst-case privacy posture.** No app
   is described as "100% private"; `privacy.leaves` states what leaves the
   device.

## The rebrand-vs-redistribute rule

Two independent permissions, both in `license`:

| | `redistribute` | `rebrand` |
|---|---|---|
| **means** | May we host the upstream binary **as-is**? | May we fork the source and ship it under **Postern branding**? |
| permissive (MIT/BSD/Apache) | yes | yes |
| copyleft (GPL/AGPL/MPL) | yes | yes — but the fork must stay open under the same license **and** drop the upstream name/logo |
| proprietary | **no** | **no** |

`trademark: true` flags the extra catch: a license can permit redistribution
while the **name/logo** stay protected. Firefox, Thunderbird, and Signal are the
classic cases — the code is free, but we may not ship a build called
"Thunderbird". Those we **link**, we do not mirror under the name. That is why a
FOSS app can still legitimately be `distribution.model = "link"`.

## Distribution models (who holds the bytes)

| model | `hosted_by_us` | who holds the binary | badge |
|---|---|---|---|
| `attest` | true | our reproducible Nix image | ATTESTED |
| `mirror` | true | our signed apk repo (unmodified upstream) | MIRRORED · SIGNED |
| `overlay-build` | true | our signed apk repo (built from source) | OVERLAY · SIGNED |
| `link` | false | upstream (Flathub / F-Droid / vendor) | LINK ONLY |
| `proxy` | false | upstream — a manifest fetches it at install | PROXY ONLY |

`attest`/`mirror`/`overlay-build` are the only models that may set
`hosted_by_us: true`; the loader clears the flag otherwise.

## Adding an app — the flow

1. **Confirm the app is real and the license is verifiable.** Never fabricate an
   app or a license. Record the exact SPDX id from the upstream `LICENSE`, and
   the upstream trademark policy if any.
2. **Decide FOSS vs proprietary — this fixes everything downstream.**
   - **FOSS** → you may `mirror`/`overlay-build` (host a signed apk in the pmOS
     overlay, see `../../pmos-overlay/DISTRIBUTION.md`), `attest` (add it to the
     Postern OS Nix image, `tier: attestable-nix`), or `link` to its upstream
     source. Prefer a repo/mirror only when trademark permits distributing under
     the name; otherwise `link`.
   - **Proprietary** → `link` or `proxy` **only**, `hosted_by_us: false`,
     `foss: false`. Give it a blunt `privacy.leaves`. It exists in the catalog
     for honesty about the boundary, not as an endorsement.
3. **Pick the `tier`** = `attestable-nix` (in the Nix image), `pmos-overlay`
   (signed apk we host), `sloboda-compat` (F-Droid / Waydroid / upstream APK),
   or `browser` (web / self-hosted). Only `attestable-nix` earns the attestable
   badge.
4. **Fill the entry** (see any entry in `catalog.json` as a template): `id`,
   `name`, `publisher` (the **upstream** author, not Postern), `category`,
   `platform`, `source`, `tier`, `oneliner`, `license{}`, `distribution{}`,
   `privacy{}`, `security[]`, `capabilities[]`, `tags[]`, `limits`.
   - Hosted entries: set `distribution.artifact` to the repo URL and leave
     `signing.state: "unpublished"` + `checksum: null` until a real build is
     published; `publish-to-r2.sh` fills them.
   - Link/proxy entries: set `distribution.upstream` and describe upstream's own
     verification in `distribution.verify`. Do **not** invent a checksum for a
     binary you don't hold.
5. **Re-sync the embedded copy.** `catalog.json` is canonical; the
   `<script id="catalog-index">` block in `index.html` must be a minified,
   semantically identical copy (compare parsed JSON, not bytes). Regenerate
   it, then verify:
   ```sh
   python3 - <<'EOF'
   import json,re
   cat=json.load(open('catalog.json'))
   emb=re.search(r'<script type="application/json" id="catalog-index">(.*?)</script>', open('index.html').read(), re.S).group(1)
   assert json.loads(emb)==cat, "embedded catalog drifted from catalog.json"
   print("in sync:", len(cat['apps']), "apps")
   EOF
   ```
6. **Sign the index.** A release of `catalog.json` is signed with the curator's
   Ed25519 key — this proves the *list* came from Postern. It does **not** attest
   each upstream binary, and the note in the file says so. Publish the detached
   signature as `catalog.json.sig` and pin the public key in `index.html`
   (`CATALOG_PUBKEY_B64`); the Store then verifies it in-page and shows
   **VERIFIED**. Full procedure — including recomputing the CSP `script-src`
   hash after pinning the key — is in [`SIGNING.md`](SIGNING.md).

## What curation is not

- Not hosting-by-default: most third-party apps are `link`, and that is honest,
  not a lesser listing.
- Not an endorsement of proprietary apps: they are listed with a blunt privacy
  posture and can never be hosted.
- Not a promise of attestation: only Nix-native apps carry that badge, and only
  because we build them from source.
