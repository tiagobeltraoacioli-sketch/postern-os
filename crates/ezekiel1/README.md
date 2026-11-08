# Ezekiel 1

Access-layer governance engine for **Consiglio** (Postern Enterprise).

> "…and their appearance and their work was as it were a wheel in the middle of
> a wheel." — Ezekiel 1:16

Ezekiel 1 governs *who may reach what*, evaluated per access, fail-closed. It is
named for the vision of the wheels:

- **Wheels within wheels** — nested access *layers* that may never widen
  themselves. A child layer nested in its parent can never carry a higher level
  than the parent that contains it.
- **Rims full of eyes** — a SHAKE-256 hash-chained, append-only audit trail that
  witnesses every grant, denial, policy change, and lowered wall. It can be
  re-verified end to end, and any rewrite is detected.
- **The firmament** — tenant isolation across which no resource id/index and no
  derived signal passes.
- **The spirit in the wheels** — per-access evaluation where the default is
  **deny**. Where the policy is silent, the answer is no.

## Status — read this first

- **UNAUDITED.** No third party has reviewed this code. Do not rely on it for
  anything that matters yet.
- **Draft (v0.1).** The public API, the policy schema, and the trail format may
  change.
- **Sovereignty stays with the data owner.** Business deployments run on the
  customer's own infrastructure. **There is no Postern server** and there is
  **zero telemetry** — no analytics, no crash reporting, no phoning home.

## Two editions

The **edition gate** is checked *first* and fails closed — a policy that names an
out-of-edition construct is refused, never quietly downgraded.

- **Personal** — parental control only. A single household, `parent -> child`
  levels, **no** Chinese walls, **no** tenants, **no** corporate roles, and
  **no spying**: inverted control (a child reaching up to a parent) is refused.
- **Business** — the full multi-level lattice (Bell-LaPadula **no-read-up /
  no-write-down**), **Brewer-Nash** Chinese walls, and **firmament-grade** tenant
  isolation.

## What it does (the pipeline)

1. **`policy`** — parse the strict governance TOML (`deny_unknown_fields`). A
   grant without an `expires` **fails to parse** (fail-closed by construction).
2. **`edition`** — the edition gate: refuse any out-of-edition construct, first.
3. **`lattice`** — build the wheel forest (parents resolve, acyclic); reject any
   child that widens past its parent; supply the no-read-up/no-write-down checks.
4. **`walls`** — validate Chinese walls (**a wall has no bypass**; `bypass = true`
   is refused) and decide **Brewer-Nash**: once a subject touches one member of a
   conflict class, every competing member is denied, permanently. Lowering a live
   wall is a deliberate owner action with a recorded reason (`Engine::lower_wall`)
   — never a config flag.
5. **`firmament`** — reject any resource id/index shared across tenants.
6. **`eval`** — the `Engine`: validate the policy, anchor a genesis trail entry
   (recording the policy hash), and evaluate each access fail-closed, recording
   every outcome to the trail. No cross-firmament cache.
7. **`trail`** — the rims-full-of-eyes audit trail: append-only JSONL, hash-
   chained with SHAKE-256 over a canonical JSON encoding, `fsync`ed per append;
   `verify_chain` recomputes the whole chain and detects any rewrite.
8. **`jobs`** — emit **Izbushka manifests** (the Yagabona schema) for the expiry
   sweep and wall audit. **Ezekiel declares; Yagabona runs.**

## Real vs. aspirational — an honest ledger

| Concern | Real, here | Aspirational / elsewhere |
| --- | --- | --- |
| No layer widens itself | Enforced: `Lattice::validate_no_widening` rejects any child level > parent | — |
| No-read-up / no-write-down | Enforced per access (business) | — |
| Chinese walls (Brewer-Nash) | Enforced with per-subject history; no config bypass | — |
| Grant expiry | Required to parse; expired grants denied at eval | — |
| Fail-closed default deny | Enforced; silence is denial | — |
| Audit trail integrity | SHAKE-256 hash chain, `fsync`ed, `verify_chain` detects rewrites | Off-host anchoring / notarization |
| **Firmament / tenant isolation** | Enforced **by construction inside one process**: distinct tenants share no resource id, cross-firmament access is refused, and each access is evaluated on its own with no cross-firmament cache — so no derived signal is threaded between tenants *through this engine* | **NOT** an OS/kernel/hardware boundary. Two tenants in one process still share an address space, allocator, and CPU; a memory-safety break, side channel, or bug outside this module could bridge firmaments. True firmament-grade isolation = separate processes/VMs/hosts per tenant on the customer's infrastructure — the deployment's job, not this crate's. |

This mirrors Yagabona's own honesty: Yagabona's filesystem boundary is a
*userland* check, not an OS sandbox; Ezekiel's firmament is *policy-correct*
isolation, not *physically inescapable* isolation.

### Follow-up

The trail here (`src/trail.rs`) is byte-for-byte the same mechanism as
`yagabona::trail` with different content fields. Both should be lifted into a
shared **`postern-trail`** crate rather than copied.

## Naming

Ships as **Ezekiel 1** — the access-layer governance component of **Consiglio**
(Postern Enterprise). The imagery (wheels within wheels, rims full of eyes, the
firmament, the spirit in the wheels) references the public-domain vision of
Ezekiel chapter 1.

## License

MIT OR Apache-2.0.
