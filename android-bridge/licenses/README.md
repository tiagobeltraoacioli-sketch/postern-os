<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# NoporIS — third-party license texts & how to keep attribution current

**Status: DESIGN scaffold. UNAUDITED. Not legal advice.**

This directory holds the **full license texts** for the third-party components
NoporIS ships or links, referenced by the sibling [`../NOTICE`](../NOTICE) and
governed by [`../COMPLIANCE.md`](../COMPLIANCE.md). NoporIS itself is licensed
**MIT OR Apache-2.0** (see repo-root `LICENSE-MIT` / `LICENSE-APACHE`); this
folder is about *other people's* code that NoporIS depends on.

## What's here

| File | Covers |
|---|---|
| [`Apache-2.0.txt`](./Apache-2.0.txt) | AOSP framework APIs, AndroidX/Jetpack, Kotlin stdlib + coroutines — every current NoporIS dependency is Apache-2.0. |

If a future dependency is added under a **different** permissive license
(BSD-2/3-Clause, MIT, ISC, Zlib, …), drop its full license text here as
`<SPDX-ID>.txt` and reference it from `../NOTICE`.

## The rule NoporIS follows

- **Permissive only.** MIT / Apache-2.0 / BSD / ISC / Zlib. **Never** GPL/AGPL/
  LGPL embedded (this also keeps the F-Droid path clean — see COMPLIANCE.md §8).
- **Every shipped component is attributed** in `../NOTICE` with its correct SPDX
  license ID, and its full license text lives here.
- **No notices stripped** from any third-party material (Apache-2.0 §4).

## How to keep this current (do this every release — it WILL drift)

This scaffold's dependency list is **inherited from the design-stage
`android-container` profile app**. NoporIS's real build has not been created, so
the manifest below is a *starting point, not ground truth*. Before any release:

1. **Resolve the real dependency graph** from NoporIS's actual build files, e.g.
   Gradle's license tooling:
   - `./gradlew :app:dependencies` to enumerate the resolved graph, and/or
   - a license-report plugin (e.g. the AboutLibraries or license-gradle-plugin)
     to emit machine-readable license metadata.
2. **Diff against `../NOTICE`.** Every resolved third-party artifact must appear
   in `NOTICE` with the right license ID; every license referenced must have its
   full text in this folder. Remove entries for dependencies that were dropped.
3. **Add any new license texts** here as `<SPDX-ID>.txt`.
4. **Regenerate the in-app "Open-source licenses" screen** from the same source
   so the shipped UI matches `NOTICE`.
5. **Re-verify AOSP.** If any AOSP source is ever *vendored* (not just compiled
   against), check its per-file license — some AOSP subtrees are BSD/MIT/other,
   and modified files must carry prominent change notices (Apache-2.0 §4(b)).
6. **Confirm zero GMS / Google binaries** shipped in the artifact (COMPLIANCE.md
   §3 / §11.C).
7. **Run the release CHECKLIST** in `../COMPLIANCE.md` §11 and get the required
   sign-offs (`LEGAL:` items go to counsel).

Attribution that silently drifts out of date is a license violation waiting to
happen. Treat regenerating `NOTICE` + this folder as a **build step**, not a
manual afterthought.

*Not legal advice — counsel review of the final license inventory is a hard
release gate.*
