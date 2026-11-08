# Postern Store × F-Droid model — repo format, client model, host-class mapping

Status: design only. No code, no deploy, no schema migration performed here.

Scope of this document (one of a three-part split):

- **This doc (01):** the repo index/package/signature format, the client's
  multi-repo trust model, how it maps onto the Store's existing three
  host-classes, and the postmarketOS install path.
- **`02-reproducible-builds.md`** (a different architect): the build
  verifier — what makes a build PASS/FAIL reproducibility and earn the
  `attestable` badge. This doc only defines the **interface** its output
  must satisfy to slot into the index (see the closing section).
- **`03-honesty-license.md`** (a different architect): the AGPL problem —
  F-Droid's own repo/build tooling (`fdroidserver`) is AGPL-3.0, and
  `deny.toml` forbids Postern forking or embedding GPL/AGPL code. This doc
  is written so the repo **format** is agnostic to which tool produces a
  compliant index — wherever a concrete generator would normally be named,
  this doc says "some generator, implementation deferred to 03" and moves on.

This design gives concrete shape to **Depot**, the "attested update + app
channel" already named as a later-phase product in
`docs/POSTERN-APPS-ROADMAP.md` (line ~110: "TUF metadata, PQ signing, build
hashes anchored to the chain … F-Droid GPL/AGPL — no code") and referenced
as the Store's "Future upgrade" in `apps/postern-store/SIGNING.md`. Nothing
here invents a new brand; it fleshes out what Depot becomes, grounded in the
F-Droid model and reusing the Ed25519-detached-signature pattern the Store
already ships today.

---

## 1. The repo format: extend `postern.catalog/v1`, don't fork it

**Decision: extend the existing `postern.catalog/v1` schema additively.**
Do not invent a parallel index format the Store consumes alongside
`catalog.json`.

### Why

The honesty machinery that makes the Store trustworthy is not documentation
— it's enforced in code, against this exact schema, today:

- proprietary ⇒ `hosted_by_us` forced false (in `normalizeEntry`)
- `attestable` security tag stripped unless `tier === "attestable-nix"`
- `signing.state !== "published"` ⇒ rendered "unpublished", checksum
  forced null
- catalog-level trust state machine (`resolveCatalogTrust`) over the exact
  served bytes

A second, parallel "F-Droid-shaped" index format would either (a) duplicate
every one of these invariants in a second code path, which *will* drift,
or (b) ship without them, which is exactly the kind of overclaiming this
codebase's culture rejects. Extending the schema in place means every
repo — Postern's own or a third party's — is a `postern.catalog/v1`
document, so one `normalizeEntry`-equivalent enforces the honesty spine
over all of them uniformly. That uniformity is also the answer to an open
design question below (§4): a third-party repo cannot "opt out" of the
invariants by writing different JSON, because the client applies the same
normalization to every repo it loads, not just the first-party one.

The extension is **wire-compatible**: every field below is optional and
additive. Today's `catalog.json` — zero `versions[]`, zero `repo{}` block —
remains a perfectly valid `postern.catalog/v1` document; a client that
doesn't understand the new fields can still render it exactly as it does
today. The schema string itself does not need to bump for this reason; if
a future breaking change is ever needed, that's a `v2` decision for
whoever makes it, not asserted here.

### What a repo-hostable document adds over today's `catalog.json`

**1a. Top-level `repo{}` — the repo's self-description.**

```jsonc
"repo": {
  "id": "com.posternlabs.store",        // stable id; namespaces apk repo tags and local pin storage
  "name": "Postern Store",
  "url": "https://posternlabs.com/store/catalog.json",   // canonical URL this index is served from
  "mirrors": [],                        // alternate URLs serving byte-identical copies
  "description": "Postern Labs' first-party curated catalog.",
  "priority": 0                          // lower = higher client-side priority; 0 reserved for the first-party repo
}
```

`repo.url` is a self-consistency check, not a trust root — see §2 for why
the client never trusts anything the index says about itself for the
purpose of establishing trust.

**1b. Per-app `versions[]` — today's single flat `distribution{}` block
becomes the latest/only entry of a version history.**

```jsonc
"versions": [
  {
    "version_name": "1.4.2",
    "version_code": 14,
    "released": "2026-07-01",
    "source": {
      "repo_url": "https://github.com/posternlabs/vault",
      "commit": "a1b2c3d4e5f6…",
      "tag": "v1.4.2"
    },
    "build": {
      "builder": "postern-os-nix@ci-runner-3",
      "toolchain": "nixpkgs-24.05 / rustc 1.79",
      "started": "2026-07-01T02:00:00Z",
      "finished": "2026-07-01T02:14:00Z"
    },
    "artifact": {
      "filename": "postern-vault-1.4.2-aarch64.apk",
      "urls": ["https://apk.posternlabs.com/v26.06/aarch64/postern-vault-1.4.2.apk"],
      "size_bytes": 4213112,
      "sha256": null                     // stays null until signing.state = "published" — same invariant as today
    },
    "signing": {
      "scheme": "abuild-rsa4096",        // or "nix-store+verity", or "ed25519-detached"
      "state": "unpublished",
      "signature": null
    },
    "reproducible_build": {              // OPTIONAL — see §7, interface from 02
      // Full field-by-field shape lives in ONE place, not duplicated here:
      // docs/store-fdroid/02-reproducible-builds.md §5, as literally
      // implemented (and enforced) by
      // apps/postern-store/reproducible-build-record.mjs. A PREVIOUS version
      // of this doc embedded a second, flatter example JSON right here
      // (`{ "schema": "postern.depot.attestation/v1", "result": "PASS",
      // "builder_identity": "<string>", ... }`) that depot/normalize.mjs
      // faithfully implemented — and that then silently diverged from
      // 02 §5's actual nested shape (`result: { verdict, ... }`,
      // `builder_identity: { id, pubkey_b64 }`), which
      // repro-verifier/lib/build-record.mjs implemented instead. A record
      // honestly produced by one could not be recognized by the other. This
      // was Depot red-team finding M4; fixed by deleting the second
      // definition, not by reconciling two copies that can drift again.
      "schema": "postern.depot.reproducible-build/v1",
      "app_id": "vault", "version": "1.4.2@<pinned-commit-or-tag>",
      "source": { "...": "see 02 §5" }, "build_env": { "...": "see 02 §5" },
      "output": { "...": "see 02 §5" },
      "result": { "verdict": "PASS", "...": "see 02 §5" },
      "run": { "...": "see 02 §5" },
      "builder_identity": { "id": "postern-verifier@ci-runner-3", "pubkey_b64": "<pinned Ed25519 pubkey>" },
      "signature": { "scheme": "ed25519", "signature_b64": "<...>", "signed_bytes_sha256": "<...>", "chain_anchor": null }
    }
  }
]
```

Notes:

- `artifact.urls` is a list to cover "multiple mirrors for the same
  version" — several byte-identical copies, same declared `sha256`. This is
  distinct from the cross-repo id-collision problem in §4, which is about
  *different repos* potentially describing *different builds* under the
  same app `id`.
- `reproducible_build` is present only where meaningful. Per §5, that's
  realistically only `tier: attestable-nix` today. Its shape is the
  interface contract with `02-reproducible-builds.md` — I do not design the
  verifier that produces it, only the record it must hand back (§ closing).
  This doc names the field; it does not re-specify its shape (see the
  `reproducible_build` example above) — that avoids exactly the two-copy
  drift M4 found.
- An entry with no `versions[]` at all (today's shape) is read as a single
  implicit version built from the existing `distribution{}` block — no
  migration required for the current file.
- `checksum` / `signing.state` at the top of an app entry (today's fields)
  keep meaning "the latest/default version's state" for backward
  compatibility with `index.html` code that doesn't yet know about
  `versions[]`.

**1c. Nothing in `vocab`, `license`, `distribution`, `security`, `tier`, or
the honesty invariants changes.** They're already exactly what a
repo-hostable format needs from the "is this app real, is this claim
honest" side. F-Droid's `index-v2.json` separates `packages` (metadata)
from `packages[].versions` (per-build data) for the same reason
`catalog.json` should: metadata doesn't change every release, build/version
data does. That shape is what `versions[]` above reproduces, adapted to
the field names Postern already uses instead of Android-specific ones
(`versionCode`, `apkName`, `nativecode`, etc., which don't apply outside
Android/Waydroid `sloboda-compat` entries).

### Tool-agnosticism (per the AGPL constraint, deferred to 03)

Nothing above names a generator. The format is: JSON with these field
names, signed with a detached Ed25519 signature over the exact served
bytes. It can be produced by hand, by a from-scratch permissively-licensed
tool, or (if 03 rules it permissible) by shelling out to unmodified
`fdroidserver` as an arm's-length external process and reshaping its
output — that call belongs to `03-honesty-license.md`, not here. The
consumer side (the Store/client) only ever reads the JSON; it has no
dependency on how it was produced.

---

## 2. Self-hostable repos: the add-repo flow

A third party (not Postern) can stand up their own repo with nothing more
than a static file host and an offline Ed25519 keypair — no coordination
with Postern required, mirroring F-Droid's model where anyone can run
`fdroidserver` and publish a repo URL.

### Standing up a repo (repo operator's side)

1. Generate an Ed25519 keypair offline. Never commit or publish the private
   half. (Exactly `pmos-overlay/keys/postern-keygen.sh`'s posture, generalized
   away from being Postern-specific.)
2. Write an `index.json` (or reuse the name `catalog.json`; the name is not
   load-bearing) conforming to `postern.catalog/v1` as extended in §1,
   including a `repo{}` block identifying this repo and an `index_signature`
   block with this repo's own `key_id` / `pubkey_b64`.
3. Sign the **exact served bytes** of that file with the same recipe already
   proven in `apps/postern-store/SIGNING.md`:
   ```sh
   openssl pkeyutl -sign -inkey repo_ed25519.pem -rawin \
     -in index.json -out index.json.sig     # raw 64-byte detached signature — NOT base64
   ```
4. Publish `index.json` and `index.json.sig` at the same origin, over HTTPS.
5. Publish the repo's **add string** out of band — a URL + key pair the
   operator hands out via their own channel (website, README, a QR code at
   a meetup): e.g. `postern-repo://apk.example.com/depot/index.json?pubkey=<base64-32-bytes>&name=Example+Repo`,
   or simply the two values shown separately for manual entry. This is the
   same trust primitive as F-Droid's repo-add URL/QR flow: the fingerprint
   travels in the **same string** as the URL, over a channel the user
   already trusts (whoever gave them the link/QR) — the client does **not**
   fetch a key from the server and trust it on first use. `index_signature.pubkey_b64`
   *inside* the served `index.json` is self-description only, exactly as it is
   in today's `catalog.json` — never the trust root.

### Adding a repo (client's side)

1. User supplies (or scans) the URL + pinned key.
2. Client stores the pin locally: `{ repo_id, url, pubkey_b64, label,
   priority, added_at, enabled: true }`. This is new client-side state the
   Store doesn't have today — it currently ships one embedded catalog and
   opportunistically re-fetches one file from the same origin. Multi-repo
   support requires a small persistent store (localStorage/IndexedDB) for
   this repo list; that's an implementation detail for whoever builds the
   client, not designed further here.
3. On every fetch of that repo, the client generalizes
   `resolveCatalogTrust(bytes)` **per repo**, against *that repo's pinned
   key*, not a single hardcoded `CATALOG_PUBKEY_B64`:

   | State | When (per repo) | Client behavior |
   |---|---|---|
   | **VERIFIED** | `.sig` present and valid for *this repo's pinned key* | render this repo's apps normally, green badge |
   | **TAMPERED** | `.sig` present but invalid for the pinned key | **reject the fetched copy.** Fall back to the last locally-cached VERIFIED snapshot of this repo if one exists; if none exists, show zero apps from this repo with a red warning — never silently drop the repo from the list, and never fall back to an unverified copy |
   | **UNSIGNED** | no `.sig` published for this repo | amber badge, apps still listed — same posture as today's offline/`file://` fallback, now per-repo instead of global |
   | **UNVERIFIED** | this browser's WebCrypto has no Ed25519 | amber badge, honest "can't verify here" — same as today, now evaluated once per browser, applied to all repos |

   The first-party Postern repo is the one case with a CSP-hash-pinned
   embedded fallback (today's mechanism, unchanged). Third-party repos have
   no embedded copy to fall back to — the "floor" for them is the **last
   verified snapshot the client itself cached**, not a shipped one. That's
   a strictly weaker floor than the first-party repo's, and the UI should
   say so rather than implying equivalent guarantees.

4. **Key rotation is unhandled by design at this stage**, and that's worth
   stating plainly rather than glossing over: if a repo operator rotates
   their signing key, every client that pinned the old key sees TAMPERED
   (or a hard verification failure) on the next fetch, with no automatic
   recovery — the user must notice, confirm the rotation out of band again,
   and re-pin. This is the same rough edge F-Droid itself has with ad hoc
   repos. It's precisely what TUF's role separation (root role signs over
   rotations of the targets/snapshot roles) is *for*, which is why Depot's
   planned TUF upgrade (§ below) is the real fix, not a client-side patch
   on top of bare Ed25519.
5. Removing/disabling a repo: its apps drop out of the merged view
   immediately. Anything already installed from it stays installed (it's on
   disk via `apk`/Nix already) but stops receiving update offers through the
   client — the underlying package manager can still be driven manually.

---

## 3. The client: multi-repo model

The Postern Store becomes a repo **client** in the F-Droid sense: it holds
a list of repos (first-party Postern + N user-added), fetches and verifies
each independently (§2), and presents a merged catalog.

### Merging

- The merged app list is the union of every enabled repo's `apps[]`, each
  entry tagged with its source repo (name + trust state), always visible in
  the UI — never collapsed away. A card never claims a badge (ATTESTED /
  MIRRORED·SIGNED / OVERLAY·SIGNED) without also showing which repo is
  vouching for it.
- **The honesty-spine normalization (`normalizeEntry`) runs identically on
  every repo's entries, first-party or third-party.** A third-party repo
  writing `license.class: "proprietary"` and `distribution.hosted_by_us:
  true` gets exactly the same downgrade Postern's own entries would: forced
  to `link`, artifact dropped. This is the practical payoff of extending
  the schema instead of forking it (§1) — one enforcement path, applied
  uniformly, with no way for a third party to write JSON that grants itself
  an exemption a first-party entry couldn't also claim.
- The `attestable` badge additionally requires (beyond `tier ===
  "attestable-nix"`) a `reproducible_build.result.verdict === "PASS"` record
  whose `builder_identity` is one the client actually trusts (see §7), bound
  to this exact `app_id`/`version` — not just a self-asserted tier string in
  the JSON. A third-party repo cannot get the ATTESTED badge by typing
  `"tier": "attestable-nix"`; it has to
  produce a verifier record the client can itself validate the provenance
  of. This is a strengthening of today's rule (which only checks the tier
  string) made necessary by the fact that, post-multi-repo, the JSON is no
  longer written exclusively by a curator we implicitly trust.

### Id collisions across repos

F-Droid's own answer: multiple repos can list the same `applicationId`; the
client shows versions from all of them and uses a per-repo *priority*
number to decide which repo's build is offered for install/update by
default. This has a known trust hazard F-Droid has faced — a newly added,
lower-trust repo can list a familiar package id, and if priority/expected-signer
handling isn't airtight, it can shadow a package the user actually meant to
get from a higher-trust repo.

Given Postern's honesty invariants, this design is deliberately stricter:

- **Id collision is never silently merged into one card.** Every `(repo,
  id)` pair is a distinct listing. If two repos both list `id:
  "signal-android"`, the UI shows two cards, each clearly labeled with its
  source repo and that repo's own trust state.
- **The first-party Postern repo is authoritative for any id it lists.** If
  a third-party repo reuses an id Postern's own catalog already uses, that
  third-party card renders with an explicit "also listed by *Postern
  Store*, not verified by this repo" cross-reference — it never inherits or
  shadows the first-party entry's badge.
- **Per-installed-app repo pinning:** once a user installs an app from a
  specific repo, the client remembers `(app id → source repo, key)` and
  only offers future updates from that same repo/key — never silently
  switches an installed app's update source to a different repo that
  happens to claim the same id. This is the Depot-layer analogue of
  Android's own "expected signing certificate" pinning per package.
- **This problem is already mostly solved at the OS level for
  `pmos-overlay` packages specifically**, independent of anything the Depot
  index does: Alpine's tagged-repository pinning (`@postern` in
  `/etc/apk/repositories`, per `pmos-overlay/DISTRIBUTION.md`) means `apk`
  itself will not satisfy a package name from an untagged/wrong repo. Depot
  index-level collision handling mainly matters for `attestable-nix`
  (Nix has no equivalent OS-level pinning exposed here) and for
  `sloboda-compat`/`browser`/`link` entries, where there is no
  package-manager backstop at all — the Depot client is the only line of
  defense for those tiers.

### Install, per host-class (client behavior)

The client's "Install" action is not one code path — it dispatches by
`tier`/`distribution.model`, described concretely in §5–6. In short:
`pmos-overlay` hands off to `apk`; `attestable-nix` has no live runtime
install path today (flagged as a hard open problem, §6); `link`/`proxy`
open the upstream location and stop — the client makes no local trust
claim beyond "the index entry describing this link is itself signed."

---

## 4. Mapping onto the five `distribution.model` values

| `model` | `hosted_by_us` | Participates in a self-hostable Depot-format repo? | Can carry a `reproducible_build` attestation? |
|---|---|---|---|
| `attest` | true | **Yes, first-class.** This is the tier the whole `versions[]`/`reproducible_build` structure exists for — a Nix build artifact with a real build-input closure. | **Yes — the only tier that realistically can, today.** Reproducibility requires a Nix host running the closure; any repo operator (Postern or, in principle, a third party running their own Nix build + the §7 verifier) can produce a valid record. Only Postern's first-party repo does this today. |
| `mirror` | true | Yes, as a normal `pmos-overlay`-tier entry: an unmodified upstream binary we host, RSA-signed via `abuild-sign`, indexed in `APKINDEX.tar.gz`. | **No.** Alpine/postmarketOS is explicitly not bit-for-bit reproducible as a distro property (`pmos-overlay/DISTRIBUTION.md`'s own disclosure: postmarketOS's reproducible-binary-repo attempt was abandoned). `abuild`/apk signing proves *who published*, never *what it was built from*. Badge stays MIRRORED·SIGNED, never ATTESTED, even in a self-hosted third-party repo. |
| `overlay-build` | true | Yes, same apk/`APKINDEX` mechanism as `mirror`, but built from source via an `APKBUILD` rather than repackaging an upstream binary. | **No**, same Alpine non-reproducibility caveat. Badge stays OVERLAY·SIGNED. |
| `link` | false | Yes, but trivially: a `link` entry in anyone's Depot-format repo is just a pointer + metadata, no artifact of ours to sign. Note `vocab.source.fdroid` already anticipates linking to upstream **F-Droid's own** repo (a genuinely different index format — `index-v2.json`/JAR-signed — that this design does not attempt to parse; see §8). | **No** — there is no artifact we hold to attest. |
| `proxy` | false | Yes, as a manifest/wrapper entry (`artifact` describes a fetch-at-install-time pointer rather than a hosted file). Honesty-equivalent to `link`; the wrapper is an ergonomics convenience, not a hosting claim. | **No**, for the same reason as `link` — nothing of ours to attest. A proxy entry *may* pass through the upstream's own published checksum for defense-in-depth, but that is the upstream's claim, not Postern's or the repo operator's. |

Only `attest`/`attestable-nix` can ever earn the ATTESTED badge, in any
repo, first-party or third-party — this is unchanged from today's rule,
just generalized to hold across the multi-repo client instead of being
implicitly true because there was only one repo.

---

## 5. postmarketOS install path, end to end

Reuses the apk/`@postern`-tag/repository-pinning machinery documented in
`pmos-overlay/DISTRIBUTION.md` without modification — the Depot index is a
**discovery and verification layer describing an apk repo**, not a
replacement for apk's own RSA-signed `APKINDEX` trust mechanism. Two
independent signature schemes are in play at once, deliberately:

1. **Depot index signature** (Ed25519, detached, over the index JSON) —
   proves *this list of packages, their metadata, and their claimed apk
   repo location* came from whoever the user pinned as this repo's key.
2. **apk repository signature** (RSA-4096, `abuild-sign`, over
   `APKINDEX.tar.gz` and each `.apk`) — proves *this specific binary* came
   from whoever holds that RSA key. This is Alpine's own mechanism,
   completely unchanged.

Concretely, for a `pmos-overlay`-tier app in a Depot repo the user has
added:

1. User adds the Depot repo by URL + pinned Ed25519 key (§2). Client fetches
   `index.json`, resolves VERIFIED.
2. User finds an app tagged `pmos-overlay` and taps Install. The entry's
   `distribution`/`versions[].artifact` carries a pointer to the underlying
   apk repo (base URL + branch, e.g. `https://apk.example.com/v26.06`) and
   the apk public-key URL (e.g. `https://apk.example.com/keys/repo-<8hex>.rsa.pub`),
   analogous to today's `distribution.artifact` field.
3. The client (or, if it has no privileged helper, the user following an
   on-screen script identical in shape to `DISTRIBUTION.md`'s existing
   snippet) performs the *exact* apk bootstrap, generalized only in the
   repo tag so multiple Depot-described apk repos never collide:
   ```sh
   # 1. Trust this repo's apk signing key (filename must stay exactly as published)
   wget -P /etc/apk/keys https://apk.example.com/keys/repo-<8hex>.rsa.pub

   # Check its fingerprint against the one the Depot index entry (or the
   # repo's own out-of-band publication) declares — a second, independent
   # check on top of the Depot index signature, not a substitute for it.
   sha256sum /etc/apk/keys/repo-<8hex>.rsa.pub

   # 2. Add the TAGGED repository — tag namespaced by Depot repo id to avoid
   #    collisions between multiple added Depot repos that each describe
   #    their own apk repo (@postern is Postern's own; a third party gets
   #    its own tag, e.g. @depot-<repo-id-slug>)
   echo "@depot-<repo-id-slug> https://apk.example.com/v26.06" >> /etc/apk/repositories

   # 3. Install, pinned to that tag
   apk add <pkgname>@depot-<repo-id-slug>
   ```
4. **Never `--allow-untrusted`**, ever, regardless of which repo the
   install is routed through — this is the one apk reflex the Store/client
   must never teach a user or automate around, unchanged from
   `DISTRIBUTION.md`.
5. Updates ride `apk upgrade` as today — no self-updater, no phoning home.
   The Depot client can *notify* that a repo's index shows a newer
   `version_code` than what's installed, but the actual upgrade is still
   the user (or a scheduled `apk upgrade`) running Alpine's own mechanism.
6. Repository pinning (`@`-tag) means a compromised or malicious Depot repo
   can still never satisfy a dependency of a base pmOS/Alpine package,
   exactly as it does for `@postern` today — this property is inherited
   for free by generalizing the tag scheme, not something the Depot layer
   has to reimplement.

For `attest`/`attestable-nix` entries reached through a third-party or
first-party Depot repo: **there is no equivalent live install step today.**
See §6.

For `link`/`proxy` entries: the client opens the upstream URL (Flathub,
F-Droid, vendor site) or, for `proxy`, resolves whatever manifest Postern
or the repo operator hosts that itself points at the upstream fetch. No apk
or Nix mechanism is invoked; the Depot layer's job ends at "here is a
verified pointer."

---

## 6. The attestable-nix install gap (stated plainly, not hand-waved)

This is a genuine, unresolved architectural tension, not a detail to
smooth over:

The F-Droid model assumes **runtime package install** — you add a repo,
you install one more app, the rest of the system is unaffected. Postern
OS's `attestable-nix` tier is built on the *opposite* assumption: an
immutable, dm-verity-sealed erofs rootfs (`os/attested.nix`) with the
roothash bound into a measured-boot UKI. Reproducibility and attestability
in Postern's current design are properties of **the whole sealed image**,
not of an individually installable package. "Installing one more
attestable-nix app after the fact" has no clean answer yet:

- A post-boot package add would break the dm-verity seal (the rootfs is no
  longer what the measured roothash says it is), defeating the entire point
  of that tier.
- A real fix looks like either (a) a second, user-writable but still
  Nix-built and independently attestable layer/overlay composed at boot
  (a `nixos-rebuild`-style closure add that produces a *new* sealed image
  and a *new* measured roothash, i.e. "install" = "rebuild and reboot into
  a new attested image"), or (b) accepting that `attestable-nix` apps are
  curated at OS-image-build time only, and runtime extensibility is simply
  out of scope for that tier — third parties can publish `attest`-tier
  Depot entries in principle (§4), but there's no user-facing install
  button for them yet.

This document does not pick between those — it's flagged here as a real
gap between the F-Droid runtime-install assumption and Postern's
immutable-image tier, worth resolving before Depot's attestable channel is
built, not something this repo-format/client design can paper over.

---

## 7. Interface expected from 02 (reproducible-build verifier)

The index format (§1b, `versions[].reproducible_build`) needs the verifier
to hand back a record with (field names above are a proposal, not a
demand — 02 owns the final shape):

- **`result`**: `PASS` or `FAIL` — no ambiguous middle state. Anything
  other than an explicit `PASS` is treated by the index/client as "not
  attestable," same posture as absence.
- **`input_hash`**: a hash of the full build-input closure (e.g. a Nix
  derivation hash / flake-lock-equivalent) — what was built.
- **`output_hash`**: a hash of the resulting artifact — should equal or be
  independently checkable against the version's own `artifact.sha256`.
- **`builder_identity`**: who/what ran the verifier (a key id or system
  identity) — the client needs this to decide whether it trusts *this*
  builder for the ATTESTED badge (§3), not just whether the JSON says
  `PASS`.
- **`timestamp`**: when the verification ran.
- Ideally, **a signature over the attestation record itself**, from a
  builder/verifier key distinct from the repo's index-signing key (role
  separation — same instinct as TUF's root/targets/snapshot split, and
  worth having even before full TUF lands). Open question back to 02: does
  the verifier produce its own detached signature over its output, or is
  the attestation record expected to only ever travel embedded inside an
  index that's already covered by the index's own signature? The latter is
  weaker (repo curator vouches for the record, rather than the record
  vouching for itself) and is what this design assumes as the near-term
  fallback if 02 doesn't produce an independent signature.
- A `report_url`/log pointer for human audit is useful but not
  load-bearing for the client's trust decision.

---

## 8. Open questions for 03 (license/honesty)

- **Generator tooling**: this format is deliberately generator-agnostic
  (plain JSON + detached Ed25519), but *something* has to produce a
  compliant index from source repos/build outputs. Whether that's a
  from-scratch permissively-licensed tool, or invoking unmodified
  `fdroidserver` as an arm's-length external process (never forked/linked),
  or something else, is 03's call — `deny.toml`'s "nothing Postern forks or
  embeds" constraint applies to whatever's chosen.
- **Consuming real upstream F-Droid repos**: `vocab.source.fdroid` already
  exists for `link`/`sloboda-compat` entries that point at F-Droid itself.
  Should the client ever become a genuine *consumer* of F-Droid's own
  `index-v2.json`/JAR-signed format (a different crypto envelope than the
  Ed25519-over-raw-bytes scheme this doc specifies) so those links can be
  richer than a bare URL? Not designed here — flagged as a scope question,
  likely entangled with the AGPL question above if any F-Droid-provided
  parsing code is involved.
- **Whether AGPL tooling can run as an arm's-length subprocess at all**
  without tripping the spirit (if not the letter) of `deny.toml` — needs a
  ruling from 03, not assumed here.

---

## Summary

- `postern.catalog/v1` is extended, not forked: a `repo{}` self-description
  block and per-app `versions[]` (source pointer, build metadata, artifact,
  signing, optional `reproducible_build`) are added, fully backward
  compatible with today's `catalog.json`.
- The Ed25519-detached-signature-over-exact-bytes scheme from `SIGNING.md`
  generalizes from one hardcoded curator key to N pinned repo keys; the
  VERIFIED/TAMPERED/UNSIGNED/UNVERIFIED state machine becomes per-repo, with
  a weaker fallback floor for third-party repos (last-cached-verified, not
  a shipped embedded copy) than the first-party repo enjoys.
- The Store becomes a multi-repo client: merged listing, honesty-spine
  normalization applied uniformly to every repo, id collisions kept
  visually distinct and never auto-merged, first-party entries authoritative
  over their own ids, per-installed-app repo/key pinning for updates.
- Of the five `distribution.model` values, only `attest`/`attestable-nix`
  can carry a reproducible-build attestation, in any repo — `mirror` and
  `overlay-build` are structurally excluded by Alpine's own non-reproducibility,
  and `link`/`proxy` hold no artifact of ours to attest at all.
- postmarketOS install reuses `apk`/`@`-tag/repository-pinning unmodified,
  with the Depot index as a discovery/verification layer on top, not a
  replacement for apk's RSA trust chain.
- The `attestable-nix` tier has no live runtime install path today — an
  honest, unresolved gap between the F-Droid runtime-install model and
  Postern's immutable sealed-image model, called out rather than papered
  over.
