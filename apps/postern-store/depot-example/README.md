# depot-example — demo Depot repos for the Store's multi-repo UI

Three same-origin fixture repos, purely to exercise the "add repo" +
per-repo trust + key-rotation UX in `../index.html` live, under the page's
real CSP (`connect-src 'self'` already covers these — no allowlist change
needed). None of these are real third-party apps; see `gen-fixtures.mjs`
for how they're produced. Private keys are never written to disk or
committed — each run of the generator makes fresh keys and discards them.

Regenerate with `node gen-fixtures.mjs` from this directory. Regenerating
changes the printed public keys — the demo instructions below become
stale until re-run and re-copied. Re-running is intentionally cheap.

## 1. `index.json` — plain VERIFIED demo

Open the Store, click **Repos → Add a repo**, and enter:

- Label: `Example Depot`
- Index URL: `./depot-example/index.json`
- Pinned key: printed by `gen-fixtures.mjs` as "VERIFIED demo"

Expect: the repo resolves **VERIFIED**, its two demo apps appear in the
catalog tagged "via Example Depot · VERIFIED". The second demo app
(`Example Corp Cloud`) is deliberately proprietary-and-claims-hosted in the
raw JSON — confirm its card still renders LINK ONLY / no artifact, proving
`normalizeEntry`'s honesty invariants run identically on third-party
entries, regardless of this repo's valid signature.

## 2. `index-rotated.json` — legitimate key rotation

- Label: `Rotated Depot`
- Index URL: `./depot-example/index-rotated.json`
- Pinned key: the **OLD** key printed as "ROTATION_PENDING demo"

Expect: the repo resolves **ROTATION_PENDING**, not TAMPERED and not
VERIFIED. Repos dialog shows an "Accept new key & re-pin" / "Reject" pair
— this is legitimate because `index-rotated.json`'s `repo.key_rotation`
block carries a transition statement signed by the OLD key you pinned,
verified before the prompt is ever shown.

## 3. `index-rotated-bad.json` — attack demo (red-team fix #5)

- Label: `Rotated Depot Bad`
- Index URL: `./depot-example/index-rotated-bad.json`
- Pinned key: the **OLD** key printed as "TAMPERED (rejected rotation) demo"

Expect: the repo resolves **TAMPERED**, full stop. There is no accept
button, no "click to trust the new key" — `key_rotation.transition_signature_b64`
in this fixture is 64 random bytes, not a real signature from the old key,
so `verifyKeyRotation()` rejects it before `resolveRepoTrust()` ever
reaches a rotation-offer branch. This is the fixture that proves an
attacker who can serve arbitrary index bytes still cannot forge a
key-rotation UI prompt without holding the old private key.
