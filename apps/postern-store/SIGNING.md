# Signing the Postern Store catalog — the scheme the Store verifies

The Postern Store renders one index file, [`catalog.json`](catalog.json)
(schema `postern.catalog/v1`). As of this change the Store is a **verifying
client** of that index: it does a real in-page cryptographic check and shows an
honest trust state, instead of only *displaying* signing metadata.

> **Live state today: SIGNED / VERIFIED.** The curator's Ed25519 public key is
> pinned in `index.html` as `CATALOG_PUBKEY_B64`
> (`xhW1EymjaCs8nAwYbFglWeGrTs4gMo8uoc2oV7nnAes=`, also mirrored in
> `catalog.json`'s `index_signature.pubkey_b64`), and a real detached
> signature `catalog.json.sig` (64 raw bytes) ships beside the index — so a
> catalog served over http resolves to **VERIFIED**. A `file://` open (no
> fetch) or a browser without WebCrypto-Ed25519 falls back honestly to the
> embedded, CSP-hash-pinned index with an **UNSIGNED/UNVERIFIED** banner; a
> tampered network copy resolves to **TAMPERED** and is rejected. The Store
> never renders a fake "verified" badge. **Only the LIST is signed** — every
> per-app HOSTED artifact still carries `checksum: null` /
> `signing.state: "unpublished"` (no apk has been built; that needs a
> Linux/pmbootstrap host — see `pmos-overlay/HONESTY.md`). The private signing
> half is never committed (`pmos-overlay/keys/postern-keygen.sh`).

## Near-term scheme: detached Ed25519 over `catalog.json`

- **Primitive:** Ed25519 (EdDSA over Curve25519), verified in-page with
  `SubtleCrypto` (`crypto.subtle.importKey("raw", …, {name:"Ed25519"})` +
  `crypto.subtle.verify`). No new dependency, no WASM, no external request — it
  fits the Store's strict-CSP, single-inline-script, dependency-free posture.
- **What is signed:** the **exact bytes served for `catalog.json`** (the whole
  file, byte-for-byte — not a re-serialization). The Store reads the response as
  text, encodes it with `TextEncoder`, and verifies the signature over those
  same bytes it then `JSON.parse`s. Sign the file, don't canonicalize it, so the
  signer and the verifier agree on the byte string trivially.
- **Signature artifact:** a **detached** signature published beside the index as
  **`catalog.json.sig`**, containing the **raw 64-byte Ed25519 signature as
  binary** — the file is exactly 64 bytes. The Store reads it with
  `arrayBuffer()` and rejects any `.sig` whose byte length is not exactly 64, so
  it must be the raw signature, **not** base64-wrapped (that would be 88 bytes
  and fail the length check). Detached keeps `catalog.json` a clean, diffable
  JSON file.
- **Public key:** the curator's **32-byte raw Ed25519 public key**, base64,
  pinned in `index.html` as the page constant `CATALOG_PUBKEY_B64` — the same
  "key is a build-time constant, shipped in the hashed page" pattern the
  marketing site uses for `OS_MINISIGN_KEY`. Pinning the key in the
  CSP-hash-pinned page is what makes the check meaningful: swapping the key means
  changing the page, which changes its sha256 and is visible in review.
- **`connect-src`:** unchanged. `catalog.json` and `catalog.json.sig` are both
  same-origin (`'self'`); no new origin is added.

### What a valid signature does and does not prove

A valid signature proves the **list came from the holder of the Postern curator
key** — i.e. the catalog you are reading is the one Postern published, unmodified
in transit or at rest. It does **not**, and cannot, attest each upstream app's
binary: KeePassXC's bytes, Signal's APK, etc. are outside this signature's scope.
Per-artifact integrity is the Depot's job (below). This mirrors the honesty note
already in `catalog.json`'s `index_signature`.

### Trust states the Store computes

`resolveCatalogTrust(bytes)` in `index.html` returns exactly one of:

| State | When | Banner |
|---|---|---|
| **UNSIGNED** | no key pinned (`CATALOG_PUBKEY_B64` null) **or** no `catalog.json.sig` present | amber "UNSIGNED" — the `file://` / offline fallback |
| **VERIFIED** | `.sig` present **and** valid for the pinned key | green "VERIFIED" |
| **TAMPERED** | `.sig` present but **invalid** for the pinned key | red "TAMPERED" — the fetched copy is **rejected**, the embedded index stands |
| **UNVERIFIED** | this browser's WebCrypto has no Ed25519 | amber "UNVERIFIED" — honest fallback, embedded index stands |

The verdict is rendered as the **catalog-signature banner** above the results
grid. It never blocks rendering: an UNSIGNED/UNVERIFIED catalog still lists apps;
only a **TAMPERED** network copy is refused (the CSP-hash-pinned embedded copy is
always the floor). The existing per-entry honesty invariants
(`normalizeEntry`: proprietary-can't-be-hosted, attestable-only-for-Nix,
`signing.state ≠ published ⇒ unpublished`) are unchanged and still enforced.

### WebCrypto Ed25519 support & the honest fallback

Ed25519 in `SubtleCrypto` is available in current Chrome/Edge (≥137), Firefox,
Safari 17+, Node ≥ 20, and Deno. Where it is **not** implemented, the Store
probes once (`ed25519Available()`), reports **UNVERIFIED** rather than guessing,
and falls back to the embedded index. We deliberately do **not** ship a JS/WASM
Ed25519 polyfill: it would add an unaudited dependency and, on the CSP side, a
WASM blob — both of which the Store's whole value proposition rejects. An honest
"can't verify here" beats an unaudited "trust me."

## Publishing a signed release (when the curator signs)

1. Generate an Ed25519 keypair (kept offline). Publish only the **public** key.
2. Sign the release bytes of `catalog.json`, e.g.:
   ```sh
   # produce a raw 64-byte Ed25519 signature (BINARY) over the exact file bytes.
   # Do NOT base64-encode it: the in-page verifier reads catalog.json.sig with
   # arrayBuffer() and requires byte length === 64.
   openssl pkeyutl -sign -inkey catalog_ed25519.pem -rawin \
     -in catalog.json -out catalog.json.sig            # raw 64-byte detached sig
   # export the raw 32-byte public key, base64, for CATALOG_PUBKEY_B64:
   openssl pkey -in catalog_ed25519.pem -pubout -outform DER \
     | tail -c 32 | base64 -w0
   ```
3. Paste the 32-byte raw public key (base64) into `CATALOG_PUBKEY_B64` in
   `index.html`, and **recompute the CSP `script-src` sha256** (see below), since
   pinning the key edits the inline script.
4. Ship `catalog.json` **and** `catalog.json.sig` to the same origin. Keep the
   embedded `<script id="catalog-index">` copy a minified, semantically
   identical copy of `catalog.json` (compare parsed JSON, not bytes —
   CURATION.md step 5). The Store will then render **VERIFIED**.

> Note: `catalog.json`'s `index_signature.scheme` currently reads `"minisign"` —
> minisign signatures *are* Ed25519, so the **key is the same**; only the file
> envelope differs (minisign wraps the signature with trusted-comment lines and
> can prehash). The Store's near-term verifier reads a **raw** detached Ed25519
> signature (`catalog.json.sig`) for a dependency-free WebCrypto check. Teaching
> it to parse the full minisign envelope is a small, optional follow-up; the
> primitive and the pinned key do not change.

## Future upgrade: the Depot (attested / PQ channel)

This detached-Ed25519 check is the honest near-term step, not the destination.
The planned **Depot** (`docs/POSTERN-APPS-ROADMAP.md`) is the signed delivery
channel the Store should ultimately verify: **TUF** metadata (role separation,
key rotation, rollback/freeze protection), **post-quantum** signing (hybrid
Falcon-1024‖ML-DSA-65, as `bloch_crypto` already does for Consiglio login), and
**per-artifact build hashes anchored to the chain**. When Depot lands, the same
in-page verifier extends from "the list is authentic" to "this TUF snapshot is
current **and** each artifact's hash matches its chain-anchored build" — the
catalog's `checksum` / `signing` fields go live instead of null. Ed25519-now is
forward-compatible: it is a subset of what TUF roles carry, and the trust-state
UI (`VERIFIED / UNSIGNED / TAMPERED / UNVERIFIED`) is the same surface.

## Recomputing the CSP hash after editing the inline script

The Store pins its one executable `<script>` by sha256 in the CSP
`script-src`. Any edit to that script (including pasting a real
`CATALOG_PUBKEY_B64`) requires recomputing the hash. The file is copied verbatim
to `public/` (no minify), so hashing the source equals hashing the served bytes:

```sh
node -e 'const f=require("fs").readFileSync("apps/postern-store/index.html","utf8");const s=f.indexOf("<script>\n\"use strict")+8;const e=f.indexOf("</script>",s);console.log("sha256-"+require("crypto").createHash("sha256").update(f.slice(s,e),"utf8").digest("base64"))'
```

Paste the printed `sha256-…` into the `script-src` of the CSP `<meta>` in
`index.html`.
