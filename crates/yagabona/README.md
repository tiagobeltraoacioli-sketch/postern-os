# Yagabona

Privacy-first scheduled-task **agent daemon** for Postern OS.

> "She does not work for the cloud. She works for you."

Yagabona (Latin *bona*, "the good Baba Yaga") is the benevolent reading of the
Slavic witch: in Propp's morphology she is the **donor** — the threshold
guardian who tests whoever approaches, rewards diligence and honesty, and
punishes overreach. A scheduled task only runs if the user has *spoken the
ritual formula*: an explicit, scoped, expiring capability grant declared in an
**Izbushka manifest** (the hut on chicken legs turns its door only to those who
ask correctly). No formula, no door.

## Status — read this first

- **UNAUDITED.** No third party has reviewed this code. Do not rely on it for
  anything that matters yet.
- **Draft (v0.1).** APIs, the manifest schema, and the trail format may change.
- **Userland boundary, not an OS sandbox.** The filesystem boundary
  (`fsboundary::ScopedFs`) is a defense-in-depth check this process performs
  against *itself* before opening any file. It is **not** kernel-enforced. It
  does not stop a compromised process from making raw syscalls or racing a
  symlink (TOCTOU). Real confinement — Linux **Landlock** / **seccomp-bpf** or
  the **macOS sandbox** — is the intended follow-up and is **not** implemented
  here.
- **Task execution is a safe stub.** `scheduler::Task` is a Rust trait, not an
  exec of arbitrary commands. This crate never spawns a shell or runs untrusted
  code.
- **Zero telemetry.** No analytics, no crash reporting, no phoning home.

## What it does

1. **Manifest** (`manifest`) — parse the strict Izbushka TOML into typed structs.
2. **Threshold Test** (`threshold::validate`) — fail-closed validation that
   yields a `Grant` or a `Refusal`. It enforces: all capabilities declared;
   every read/write path canonicalizes to *inside* the workspace root (rejecting
   `..` and symlink escapes after canonicalization); network is `none` or exactly
   `api.anthropic.com`; `expires` is present and in the future; no inline secret
   (heuristic); capabilities do not obviously exceed the description (heuristic).
   **Nothing executes on a refusal.**
3. **The glowing skull** (`trail`) — an append-only JSONL audit trail,
   hash-chained with SHAKE-256 over a canonical JSON encoding, `fsync`ed on every
   append. `verify_chain` recomputes the whole chain and detects any rewrite.
4. **Scoped filesystem boundary** (`fsboundary`) — the runtime check described
   above.
5. **Scheduler** (`scheduler`) — parse the schedule string (`daily 02:30`, …),
   compute the next fire, and a `Runner` that re-checks expiry/revocation before
   running the stubbed task inside its grant and recording every outcome.

## Izbushka manifest

```toml
[task]
name        = "nightly-notes-index"
description = "Index ~/Notes into a local search db every night"
schedule    = "daily 02:30"
expires     = "2026-12-31T23:59:59Z"

[capabilities]
read_paths  = ["~/Notes"]
write_paths = ["~/.local/share/izbushka/index"]
network     = "none"           # or "api.anthropic.com" — nothing else exists

[ritual]
granted_by  = "tiago"
granted_at  = "2026-07-11T14:02:00-03:00"
formula     = "izbushka-turn-your-face-to-me"
```

> Path resolution note: the crate confines every declared path to a
> `workspace_root` you pass to `validate`. Expanding user shorthand like `~/`
> to an absolute in-workspace path is the Izbushka UI layer's job, upstream of
> this crate.

## Naming & trademark

Ships as **Yagabona** and **Izbushka** — coined/transliterated marks that
reference public-domain folklore. It is deliberately **never** called
"Baba Yaga": that word mark is federally registered by third parties in
Class 9 (the software class). Folklore is public domain; the string
"BABA YAGA" in Class 9 is not.

## License

MIT OR Apache-2.0.
