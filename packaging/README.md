# packaging/ — Postern update-channel scaffolding (DEV-ONLY, UNAUDITED)

Earliest vertical slice of the roadmap line "Packaging — … TUF update channel
(`tough`)" (docs/POSTERN-ROADMAP.md, `in-progress`). Everything here is a
local, dev-keys-only scaffold. Like the rest of this repository it is
UNAUDITED and pre-mainnet.

## What exists

- `tuf-channel/` — `postern-tuf`, a standalone Rust crate (its own empty
  `[workspace]` table, intentionally NOT a member of the root workspace —
  same pattern as `integration/pairing`). Built on
  [`tough`](https://github.com/awslabs/tough) (AWS Labs, MIT OR Apache-2.0).
  Six subcommands:
  - `init <repo-dir>` — generate ed25519 dev keys (into
    `dev-keys-DO-NOT-SHIP/`, README included) and write signed
    root/targets/snapshot/timestamp metadata with short dev expiries.
  - `add-target <repo-dir> <file>` — hash+length an artifact into targets
    metadata, copy it into `targets/`, re-sign targets/snapshot/timestamp.
  - `verify <repo-dir> <target-name>` — full fail-closed TUF client load
    (expired or tampered metadata is a hard error), fetch the target, print
    its SHA-256.
  - `rotate-root <repo-dir>` — root key rotation per TUF spec 5.3.4:
    generate a fresh ed25519 dev key, build root vN+1 (bumped version, new
    root keyid, targets/snapshot/timestamp keys unchanged), sign its
    canonical-JSON bytes with BOTH the old and the new root key, write
    `N+1.root.json` alongside `1.root.json`, retire the old key file to a
    `.retired` name. A client still pinned to `1.root.json` rolls forward
    through the chain; a rotated root carrying only the NEW key's signature
    is rejected fail-closed. The swap is not atomic but IS crash-recoverable:
    the incoming key is staged (`root.pkcs8.der.staged`) before the rotated
    root is written, and a rotation interrupted mid-swap is detected and
    finished (or a never-blessed staged key discarded) by the next
    `rotate-root` run — no manual key-file surgery. HONESTY: this is a LOCAL
    exercise of the rotation rule with throwaway dev keys — it is NOT a key
    ceremony, NOT a custody plan, and nothing signed here may ever ship to a
    user.
  - `refresh <repo-dir>` — re-sign snapshot + timestamp with bumped versions
    and fresh (short, dev) expiries, targets metadata preserved byte-for-byte
    — the anti-staleness operation a real channel would run on a schedule. No
    scheduler and no endpoint exist here; it exercises the operation, it
    does not operate a channel. Refresh can only refresh a repo that still
    verifies TODAY: once snapshot/timestamp have already lapsed (7/14 dev
    days), the fail-closed load rejects the repo and refresh errors out. A
    quiet dev repo therefore rots by design; that lapse is exactly what
    `recover` (below) exists for, and the boundary is kept, not blurred.
  - `recover <repo-dir>` — the designed lapse-recovery rule. For a repo whose
    snapshot/timestamp have LAPSED but whose root chain is still within its
    own expiry and whose signing keys are present, recover (a) re-derives the
    trust anchor by walking the `1.root.json → N.root.json` rotation chain
    under the same dual rule the client enforces, (b) re-verifies
    `targets.json`'s signature against the trusted root's targets key, and
    (c) re-hashes every file under `targets/` against its recorded
    hash+length — all BEFORE re-signing fresh, bumped snapshot/timestamp
    (`targets.json` preserved byte-for-byte). Any signature, hash, length,
    unlisted-file, or missing-key failure is a hard error, and an expired
    ROOT is a hard error directing the operator to full re-init: recovery
    never resurrects trust it cannot re-derive from still-valid root
    metadata. A repo that still verifies is refused (that is `refresh`'s
    job). HONESTY: dev keys, LOCAL repo — this exercises the recovery RULE;
    it is not an operated channel.
  Integration tests: `tests/roundtrip.rs` covers the honest round trip plus
  two fail-closed cases (tampered `targets.json`, tampered artifact bytes);
  `tests/rotation.rs` covers rotation roll-forward from the pinned
  `1.root.json`, rejection of a new-key-only root (unauthorized rotation,
  fail closed), refresh version bumps with `targets.json` asserted
  byte-identical, a two-rotation chain, crash-recovery of an interrupted
  key swap, discard of a never-blessed staged key, and refresh failing
  closed on an already-expired repo; `tests/recovery.rs` covers the honest
  lapse → recover → verify round trip (with the refresh/recover boundary
  asserted from both sides and `targets.json` byte-identical), and recover
  failing closed on a tampered `targets.json`, a tampered artifact, a
  resized artifact, an expired root (with the re-init message), a missing
  signing key, and an unlisted file under `targets/`.
- `release-manifest/` — `postern-release-manifest`, a second standalone Rust
  crate (same own-empty-`[workspace]` pattern; the frozen root workspace is
  untouched). It REUSES the existing hybrid signer in `crates/postern-release`
  as a path dependency — no crypto is duplicated and that crate is not
  modified. Subcommands:
  - `build <bundle-dir> <manifest-path>` — walk the bundle dir's regular
    files (flat, skipping its own manifest/signature outputs and
    `SHA256SUMS`) and emit `release-manifest.json`: `schema_version`,
    `created_at` (RFC 3339), an embedded honesty note (dev-keys-only /
    UNAUDITED / LOCAL / complements-not-replaces-minisign), and a sorted
    `artifacts` array of `{name, size, sha256}`. An empty bundle dir is a
    hard error. `created_at` honors `SOURCE_DATE_EPOCH` (the
    reproducible-builds convention): with it set, two `build` runs over an
    identical bundle dir are BYTE-IDENTICAL, and a set-but-malformed value
    is a hard error (a silently ignored knob would fake determinism).
    DETERMINISM SCOPE, honestly: this pins the MANIFEST bytes only —
    "reproducible where the platform allows" starts and ends at the
    manifest/metadata layer here; the bundle ARTIFACTS the manifest
    describes (.dmg, .deb, …) are NOT claimed bit-reproducible.
  - `keygen <key-prefix>` — fresh HYBRID Falcon-1024 + ML-DSA-87 DEV keys
    (same four-file convention as the `postern-release` CLI).
  - `sign <manifest-path> <key-prefix> [sig-path]` — detached hybrid
    signature (`.pqsig`) over the exact manifest bytes, via
    `postern_release::sign::sign_manifest`.
  - `verify <bundle-dir> <manifest-path> <pub-prefix> [sig-path]` — checks
    the hybrid signature (AND-of-both: one corrupted leg rejects the pair,
    `postern-release`'s rule) AND re-stats + re-hashes the bundle dir
    against the manifest. Any size/sha256 mismatch, missing artifact, or
    unlisted file is a hard error — fail closed, never a warning.
  Integration tests (`tests/roundtrip.rs`) cover the honest
  build→sign→verify round trip plus fail-closed cases: one flipped manifest
  byte, an artifact modified/grown/deleted after `build`, an unlisted file,
  one corrupted signature leg (either leg), and an empty bundle dir.
  `tests/determinism.rs` (its own process, because it mutates the
  environment) proves two `SOURCE_DATE_EPOCH` builds byte-identical, a
  malformed `SOURCE_DATE_EPOCH` a hard error, and the no-epoch fallback
  still valid RFC 3339.
- `build-signed-bundle.sh` — end-to-end local pipeline: bundle dir (or
  `--self-test` dummy artifact) → SHA256SUMS → `postern-release-manifest
  build` / `keygen` (fresh dev keys into `dev-keys-DO-NOT-SHIP/`) / `sign` /
  `verify`, with every manifest sha256 cross-checked against the SHA256SUMS
  line for the same file (any mismatch dies) → `postern-tuf init` /
  `add-target` / `verify`, with a hash cross-check between the TUF-verified
  bytes and SHA256SUMS. `--self-test` additionally (a) builds the manifest
  twice under the same `SOURCE_DATE_EPOCH` and requires the two outputs to
  be byte-identical (the determinism proof — manifest bytes only, see
  above), and (b) tampers with the artifact after signing and requires
  `verify` to fail (fail-closed proof). The lapse-recovery rule is
  deliberately NOT exercised in this script (its primary proof is the
  `tests/recovery.rs` cargo tests; forcing a lapse needs test-only expiry
  surgery that does not belong in the operator pipeline).

Run it:

```sh
cd packaging/tuf-channel && cargo test
cd packaging/release-manifest && cargo test
bash packaging/build-signed-bundle.sh --self-test
```

## Recovery / re-init design (the real-channel story)

The roadmap requires an explicit, designed recovery/re-init story before a
real channel can exist. This is that design, ordered from routine to
catastrophic — each tier is strictly about what trust can still be
RE-DERIVED, never about resurrecting what cannot:

1. **Root rotation (routine, invisible to clients).** A client is pinned to
   `1.root.json` and nothing else. Root keys rotate via `rotate-root` (TUF
   spec 5.3.4 dual-signing): every `N+1.root.json` is signed by BOTH the
   outgoing and the incoming root key, so the pinned client rolls forward
   through the whole chain on its own. Clients survive any number of
   rotations without re-pinning; a rotated root carrying only the new key's
   signature is rejected fail-closed. This is the ONLY key-change event a
   client survives automatically — everything below is worse.

2. **Lapse (operational failure, operator-recoverable).** Snapshot/timestamp
   expired because the refresh schedule was missed. Nothing about the trust
   root changed; clients simply (and correctly) refuse the stale repo. The
   recovery is `recover`: re-derive the trust anchor from the still-valid
   root chain, re-verify targets content (signature + every artifact's
   recorded hash+length), then re-sign fresh snapshot/timestamp. Clients
   need no action at all — the next load just succeeds again. Recovery
   fails closed on ANY discrepancy, because a lapsed repo is exactly where
   an attacker would hide a swap: freshness is re-signed, content never is.

3. **Root expiry or root-key loss (a trust event, not maintenance).** If the
   root itself expired, or the root key is lost/compromised, there is no
   still-valid metadata left to re-derive trust from — and `recover` refuses
   to pretend otherwise (hard error, pointing here). The only path is
   re-init: a NEW `1.root.json`, i.e. a NEW trust root, which every
   installed client must re-pin OUT-OF-BAND (a new pinned root shipped
   through a channel the broken one cannot influence — e.g. a new signed
   app release, or manual verification against a published fingerprint).
   That is the same trust decision as the original install, and this design
   states it as such rather than automating it away: any mechanism that
   would let a repo "recover" from an expired root without out-of-band
   re-pinning would also let an attacker holding stale keys do the same.

4. **Why `createUpdaterArtifacts` stays `false` through all of this.** The
   tiers above are exercised locally with throwaway dev keys; none of it is
   an operated channel. Flipping the desktop updater on requires the things
   this directory intentionally does not have: real keys under a real
   custody/ceremony plan, a real endpoint with an operated refresh schedule
   (so tier 2 never happens by neglect), and an audit. Until those exist,
   `desktop/tauri.conf.json` keeps `createUpdaterArtifacts = false`,
   enforced by `desktop/tests/bundle_config.rs` — and nothing in this
   directory may be cited as a reason to flip it.

## OS / file-manager embed (Hygiene) — wired

The roadmap line "OS/file-manager embed not wired yet" (Hygiene) is now filled.
The scrubber's stdin/stdout embed mode (`postern-hygiene scrub -` / `check -`,
black-box tested in `crates/postern-hygiene/tests/cli.rs`) is wired into a
native right-click action under **`desktop/file-manager/`**:

- `postern-scrub.sh` — the shared glue: pipes each selected file through
  `postern-hygiene scrub -` into a non-clobbering `.scrubbed` sibling
  (`photo.jpg` → `photo.scrubbed.jpg`). Fail-closed — a non-zero scrub deletes
  the partial output, so a failed scrub never leaves a half-scrubbed file.
- Linux: a freedesktop `.desktop` Desktop-Action (KDE ServiceMenus /
  nautilus-actions) **and** a GNOME Files/Nautilus **Scripts** drop-in.
- macOS: an Automator **Quick Action** (`.workflow`) that shows up under Finder
  → Quick Actions and runs the same shared script.
- `install.sh` installs the right integration per-OS (per-user, no root);
  `--uninstall` reverses it. It does NOT install the `postern-hygiene` binary —
  build that (`cargo build -p postern-hygiene`) and put it on PATH, or export
  `POSTERN_HYGIENE_BIN`.

Acceptance: `desktop/file-manager/test-scrub-action.sh` synthesizes a real
EXIF-tagged JPEG and an OOXML with `docProps` author metadata, runs the action,
and asserts each scrubbed sibling reports **clean** via `postern-hygiene check
--json`. The same check runs hermetically under Cargo:
`cargo test -p postern-hygiene --test file_manager_action` (no python needed;
skips on hosts without `/bin/sh`). This is GUI glue over the existing pipe —
still UNAUDITED, no new crypto, no new claim.

## What does NOT exist

- No live update server or endpoint. All metadata is LOCAL.
- No real signing keys. Every key ever produced here lives in a directory
  named `dev-keys-DO-NOT-SHIP` and must never leave the machine.
- No desktop integration. `desktop/` keeps `createUpdaterArtifacts = false`
  in its Tauri config (enforced by `desktop/tests/bundle_config.rs`) until
  the channel is real — real keys, real endpoint, audit. Nothing in this
  directory changes or weakens that.
- No PQ signing beyond the dev release manifest: `release-manifest/` signs
  `release-manifest.json` with Falcon-1024‖ML-DSA-87 (reusing
  `crates/postern-release`), but only ever with fresh throwaway dev keys —
  it proves origin+integrity of that manifest on YOUR machine and nothing
  more. It is NOT attestation, NOT a reproducibility proof, NOT an audit,
  and it COMPLEMENTS (does not replace) the repo's minisign convention.
  No multi-platform bundling, no reproducible-build attestation, no
  chain-anchored build hashes. One flat bundle dir end-to-end is the slice.
- No artifact reproducibility. `SOURCE_DATE_EPOCH` determinism covers the
  manifest/metadata layer ONLY: the bundle ARTIFACTS themselves (.dmg,
  .deb, .AppImage, .msi, …) are NOT claimed bit-reproducible.
- No audit. UNAUDITED, like everything else in this repo.

## License note

Per docs/POSTERN-APPS-ROADMAP.md (Depot row): `tough` is AWS, MIT OR
Apache-2.0 — fine to depend on. F-Droid is the *model* for self-hosted,
reproducible app distribution, but F-Droid code is GPL/AGPL: **model only,
NO code**, and none is used here. The full dependency tree of `tuf-channel`
was checked to be permissive-only (MIT/Apache-2.0/BSD/ISC/Unlicense/Zlib/
Unicode; the single `LGPL-2.1-or-later` mention is `r-efi`'s
`MIT OR Apache-2.0 OR LGPL-2.1-or-later` tri-license, used under MIT).
The `release-manifest` tree was checked the same way (`cargo metadata`
license fields): permissive-only (MIT/Apache-2.0/Unicode/Unlicense/CC0/
MIT-0, plus the same `r-efi` `MIT OR Apache-2.0 OR LGPL-2.1-or-later`
tri-license used under MIT). `pqcrypto-falcon` vendors PQClean C under
permissive terms — and, as `crates/postern-release` already documents,
PQClean is UNAUDITED C. No GPL/AGPL anywhere.
