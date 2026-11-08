# `fixtures/` — POC test-only, not production material

Everything in this directory (and `dist/` beneath it) belongs to the
`postern-store/repo-poc` proof-of-concept and exists only so its scripts and
`test/` suite run end-to-end without a human provisioning real infrastructure
first. Nothing here is a real credential or a real published repo.

- `repo-key.json` — an **intentionally public** Ed25519 test keypair (see the
  `_WARNING` field in the file itself). It is committed on purpose: the
  checked-in `dist/index.json.sig` and `dist/revocations.json` are signed
  with this exact key, so removing it would break `verify-cli.mjs` /
  `verify-crl-cli.mjs`'s default demo path. Regenerate it any time with
  `node scripts/gen-keys.mjs`, then re-run `scripts/build-index.mjs` and
  `scripts/build-crl.mjs` to re-sign `dist/` with the new key.
- `dist/` — generated demo output (`index.json`, `index.json.sig`,
  `revocations.json`) committed so the verify scripts have something to
  check against without a build step. Regenerate via the scripts above.

Per `apps/postern-store/SIGNING.md`: in a **real** deployment the private
signing half is never committed. This directory is the one deliberate,
clearly-labeled exception, scoped to this POC only.
