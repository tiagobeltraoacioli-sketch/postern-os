# `fixtures/` — POC test-only, not production material

This directory belongs to the `postern-store/repro-verifier` proof-of-concept.
Nothing here is a real credential.

`builder-key.json` (an Ed25519 test keypair) is **not committed**. Unlike
`repo-poc/fixtures/repo-key.json`, no signed artifact is checked into this
repo that depends on this specific key — `npm test` generates its own
throwaway keypairs at runtime (see `test/record.test.mjs`'s
`generateKeypair()` calls), and the manual CLI demo flow
(`scripts/sign-record.mjs`, `scripts/verify-record-cli.mjs`) fails with a
clear instruction if the file is missing. So there is nothing gained by
committing it, and doing so previously put a real-looking private key in git
history.

To use the CLI demo locally:

```sh
node scripts/gen-builder-keys.mjs        # writes fixtures/builder-key.json (gitignored)
node scripts/sign-record.mjs <record.json>
```

Per `apps/postern-store/SIGNING.md`: in a **real** deployment the private
signing half is never committed. This POC follows that rule at rest; the key
only ever exists on disk as a locally generated, gitignored artifact.
