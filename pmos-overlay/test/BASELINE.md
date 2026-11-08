# pmOS overlay -- shellcheck baseline (known, UNFIXED issues)

This file is the exact, machine-checked list of shellcheck findings in the
read-only overlay/flavor/build scripts that `test/lint-shell.sh` has decided
are **true positives worth fixing later**, not false positives.

Read this file's status column literally: every entry below is an **open,
unfixed** finding. Nothing in this file has been resolved. `test/lint-shell.sh`
compares the *current* shellcheck output for these files against the exact
fingerprints listed here -- if a listed finding stops reproducing (someone
fixed it) or a new one shows up that isn't listed, the gate fails until this
file is updated to match reality. See "How to update this baseline" below.

This workstream's scope is `pmos-overlay/test/` only, so none of the
underlying scripts were touched to fix these -- that is deliberate, not an
oversight. See the top-level task note in the accompanying report.

## Machine-readable fingerprints

`test/lint-shell.sh` parses only the lines below matching `^BASELINE: `.
Format: `BASELINE: <path>:<line> <SCcode>`. Do not hand-edit the human table
below without also updating the matching line here -- they must describe the
same finding.

```
BASELINE: overlay/etc/init.d/postern-firewall:40 SC2015
```

## Details

| File:Line | Code | Severity | shellcheck says | Status |
|---|---|---|---|---|
| `overlay/etc/init.d/postern-firewall:40` | SC2015 | info | `nft list table inet postern >/dev/null 2>&1 && \` / `einfo "...loaded" \|\| einfo "...not loaded"` -- `A && B \|\| C` is not if-then-else; `C` can still run if `B` itself fails, not only when `A` fails. | **Known, unfixed.** Not believed to be a live bug today: `B` here is `einfo`, OpenRC's status-echo helper, which does not fail in normal operation, so in practice this always reports the correct state. It is still worth tightening to an explicit `if ...; then ...; else ...; fi` for defense-in-depth (a future OpenRC/busybox change to `einfo`'s exit behavior would silently mis-report firewall status). Out of scope for this `test/`-only workstream because fixing it means editing `overlay/etc/init.d/postern-firewall`, which is outside `pmos-overlay/test/`. |

## False positives (NOT baselined here -- suppressed at the shellcheck invocation instead)

These are handled directly in `test/lint-shell.sh`'s per-file shellcheck
arguments, each with a one-line justification comment in that script, and are
listed here only so the two files stay cross-referenced:

- **SC1008** (`#!/sbin/openrc-run` unrecognized shebang) on the three
  `overlay/etc/init.d/*` scripts -- real interpreter is POSIX sh on
  postmarketOS/Alpine; told to shellcheck via `-s sh`.
- **SC2148** (no shebang) on `overlay/usr/libexec/postern/postern-common.sh`
  and the two `overlay/etc/conf.d/*` files -- these are intentionally
  shebang-less, `.`-sourced fragments; told to shellcheck via `-s sh`.
- **SC1091** (can't follow sourced file) on `overlay/etc/init.d/postern-node`
  and `overlay/etc/init.d/postern-tor`, which `.`-source
  `/usr/libexec/postern/postern-common.sh` by its *installed* absolute path
  -- resolved for shellcheck via `-x -P overlay` against the repo-relative
  `overlay/usr/libexec/postern/postern-common.sh`.
- **SC2034** ("appears unused") on the OpenRC-framework special variables
  (`name`, `description`, `command`, `command_args`, `command_user`,
  `pidfile`, `output_log`, `error_log`, `supervisor`, `postern_*`,
  `supervise_daemon_args`) in the three `init.d` scripts and two `conf.d`
  fragments -- these are read by the OpenRC `openrc-run` framework that
  sources/evals the script, not by the script's own text, which is exactly
  the blind spot shellcheck warns it has.

None of these are blanket, project-wide, or rule-wide disables: each is a
`--exclude=SCxxxx` (or `-s sh` / `-x -P overlay`) scoped to the specific
handful of files where the false-positive reasoning above applies, applied at
the `shellcheck` invocation in `test/lint-shell.sh`, never inside the target
scripts themselves.

## How to update this baseline

If a future change to one of the read-only overlay scripts fixes the SC2015
finding above (e.g. rewrites the `status()` function as an explicit
`if/then/else`), `test/lint-shell.sh` will start failing with a "baseline
entry no longer reproduces" error. That failure means: delete the
corresponding `BASELINE:` line above and its table row -- do NOT mark it
"fixed" and leave it in place, and do NOT treat the failure as a bug in
`lint-shell.sh` to be silenced.

If a change introduces a genuinely new shellcheck finding in one of these
files, `test/lint-shell.sh` will fail with a "NEW finding" error. Triage it
the same way this file was built: either (a) it's real -- add a
`BASELINE:` line + table row here, still labeled unfixed, or (b) it's a
shellcheck false positive for a documented structural reason (OpenRC
contract, sourced-fragment-with-no-shebang, absolute install-path source,
etc.) -- add a scoped `--exclude=SCxxxx` for that exact file in
`test/lint-shell.sh` with a one-line justification, not a blanket disable.
