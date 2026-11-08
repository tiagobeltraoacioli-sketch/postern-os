# pmos-overlay/test — repeatable lint + cross-file drift guard

This directory is a small, static test harness for the
**"Postern for postmarketOS — community edition"** overlay
(`pmos-overlay/`). Run it with:

```sh
sh pmos-overlay/test/run-checks.sh
```

## What this harness IS

Two checks, run in order by `run-checks.sh`:

1. **`lint-shell.sh`** — `sh -n` (POSIX-sh syntax parse) followed by
   `shellcheck` (static analysis) over an explicit, hand-maintained list of
   every shell script in the overlay, including its own scripts
   (`test/run-checks.sh`, `test/lint-shell.sh`, `test/check-drift.sh` are
   all in that list — the harness lints itself). shellcheck's findings are
   reduced to a `path:line SCcode` fingerprint set and compared *exactly*
   against `test/BASELINE.md`: a brand-new finding fails the gate, a
   previously-baselined finding that stops reproducing also fails the gate
   (drift — `BASELINE.md` must be updated to match reality), and a handful
   of documented shellcheck false positives (OpenRC's `#!/sbin/openrc-run`
   shebang, its framework-consumed special variables, and sourced-fragment
   files with no shebang of their own) are suppressed at the shellcheck
   invocation itself, per file, each with a one-line justification — see
   `BASELINE.md` for the exact list and the one true positive (SC2015 in
   `overlay/etc/init.d/postern-firewall`) that is recorded there as a known,
   *unfixed* issue rather than fixed or silenced.
2. **`check-drift.sh`** — cross-file **string agreement**: it derives the
   published `.apk` filename from each APKBUILD's `pkgname`/`pkgver`/
   `pkgrel`, and checks that string appears verbatim in `PUBLISHED.md` and
   `build/verify-apks.sh`; it does the same for the alpha signing-key
   basename (`builder-6a52d247.rsa.pub`) across `PUBLISHED.md` and
   `build/verify-apks.sh`.

Both are **static, host-side, text-only checks**: `sh -n`, `shellcheck`,
`grep`/`sed` over plain-text files — no network, no root, no abuild. This
harness runs the same way on a laptop as it would in CI, with nothing
installed beyond `sh` and `shellcheck`. A host without `shellcheck` is a
**hard failure** (exit 1), never a degraded `sh -n`-only pass — the
`$SHELLCHECK` env var can point `lint-shell.sh` at a specific binary.

## What this harness IS NOT — read this before trusting a green run

- It does **not build** anything — no `abuild`, no package is ever
  assembled, no source tarball is ever fetched.
- It does **not boot** anything — nothing here touches a device, an
  emulator, or a disk image.
- It does **not sign** anything — no key is loaded, no signature is
  produced or checked.
- It does **not attest** anything — a green run says the *source text* in
  this tree is internally consistent, nothing about what would happen if
  it were built.
- The scripts it lints (`build/verify-apks.sh`, `build/build.sh`,
  `publish-apk-repo.sh`, the OpenRC runscripts, etc.) are **syntax/lint-checked
  only, never executed on a booted device by this harness.** `lint-shell.sh`
  parses and lints their source text; it never runs them.
- It makes **no claim of attestation, no claim of device testing, and no
  claim of a security audit.** None of those things happened here.

## Caveats this harness does not change (carried forward from ../HONESTY.md,
## ../PUBLISHED.md, and ../build/verify-apks.sh — read those for the full text)

- The published packages are **non-attestable and not reproducible
  byte-for-byte.** Per `../build/verify-apks.sh`'s own header: a source-hash
  match is exact, but a rebuilt package payload match ("same files, same
  content") is the most that is ever claimed — never a byte-identical
  rebuild of the `.apk` container, and never attestation.
- This is the **community edition**, and it is **NOT Postern OS**. Only the
  Nix-built, verity-sealed Mobile NixOS images are ever called "Postern OS"
  (`../HONESTY.md`). This harness's green output does not change that
  labeling rule, and does not itself make any "Postern OS" claim.
- The signing key `builder-6a52d247` is an **alpha build key** — "this
  build, this key", not a long-lived anchor (`../PUBLISHED.md`,
  `../build/verify-apks.sh`). `check-drift.sh` only checks that this key's
  *name* is spelled the same way everywhere; it says nothing about the
  key's trust level, which remains alpha.

## When this gate fires

`check-drift.sh` exists because the apk filename and the signing-key name
are written down **more than once, on purpose**, in different files for
different audiences:

- `postern/APKBUILD`, `postern-wallet/APKBUILD`, `postern-apps/APKBUILD`
  — the build recipe (`pkgname`/`pkgver`/`pkgrel`).
- `../PUBLISHED.md` — the human-facing "what is actually published" record.
- `../build/verify-apks.sh` — the verification script's hardcoded
  `APK_META`/`APK_WALLET`/`APK_APPS`/`KEY_URL` values.

**Any rename of an apk, a `pkgver`/`pkgrel` bump, or a signing-key rotation
requires updating `APKBUILD` + `PUBLISHED.md` + `verify-apks.sh` together.**
The duplication is intentional: it exists precisely so that a rename or
version bump made in only one of those three places is caught by
`check-drift.sh` failing, instead of silently drifting until someone
notices published bytes don't match what the docs or the verifier expect.

## Exit status

`run-checks.sh` runs `lint-shell.sh` then `check-drift.sh`, always runs
both (a `lint-shell.sh` failure does not skip `check-drift.sh`), prints one
`run-checks: PASS <script>` or `run-checks: FAIL <script> (exit N)` summary
line per check, and exits with the **first** nonzero exit code among the
two — `0` only if both checks passed.
