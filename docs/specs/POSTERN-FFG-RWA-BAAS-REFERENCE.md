# Postern FFG / RWA / BaaS — reference state kernels

> **Status: REFERENCE SCAFFOLD.** Unaudited; nothing here is operational,
> built for production, offered, or backed by any real asset. **Not legal or
> financial advice, and not an offer or solicitation of anything.** The code
> lives in the standalone `ffg/` crate (`postern-ffg`, zero dependencies in
> the default build) and exists to give the RWA and BaaS roadmap rows a
> deterministic, testable *shape* — not a product.

## What this is

The owned-layer (Layer-2) reference implementation of the anchoring pattern
from [`POSTERN-ROADMAP.md`](../POSTERN-ROADMAP.md) §5, as three modules in
`ffg/src/`:

| Module | What it references |
|---|---|
| `kernel` | A generic **deterministic state kernel**: append-only op log, pure `apply(state, op) -> Result<state>`, chained commitment root `root_{i+1} = SHAKE-256(prev_root ‖ canonical op encoding)`. Replaying the same log from the same genesis always yields the same root; reordering or tampering with one op changes it. |
| `rwa` | An **asset-registry reference kernel** on top of `kernel`: `RegisterAsset` / `Transfer` / `Redeem` / `Freeze` ops with balance/ownership invariants enforced in the pure `apply`. Every asset record carries a mandatory `legal_review: LegalGate` field — see the HARD GATE below. |
| `baas` | A **multi-tenant reference host**: N isolated kernel instances keyed by tenant id, each with its own root chain (the tenant id is bound into the genesis root). One batch anchor = SHAKE-256 over the sorted `(tenant_id, root)` pairs, written as **ONE ordinary base transaction**. Tenants share nothing. |

The SHAKE-256 used is an in-crate, zero-dependency implementation
(`ffg/src/hash.rs`) whose helper API mirrors the sibling
`l2/bloch-l2-prover/src/hash.rs` spec (length-prefixed u64-LE domain
separation); it is pinned to the NIST FIPS 202 test vectors in its tests and
that is the entire extent of its assurance — it is **unaudited**.

## Where state lives (the whole trick)

**State lives ONLY in the owned layer.** The ownerless Bloch-SIS-PoW base
never sees a kernel's state, ops, tenants, or even that a kernel exists. Per
batch, the operator may write a single opaque **32-byte root** to the base as
an **ordinary transaction** via the crate's existing `BlochAnchorClient` —
exactly the way any user writes data to an ownerless chain. No reserved
namespace, no consensus privilege, no exclusivity.

An on-base commitment proves only **"a signer asserted this root"** — never
that any asset exists or is redeemable, never that the state behind the root
is correct or complete.

**The ownerless-base test, in code:** the crate's
`postern_vanishes_and_the_base_is_untouched` test drops the anchor client
(Postern vanishes) and asserts the mock base's headers/state are byte-identical
to before — the kernels keep applying ops locally and merely stop anchoring.
The base never depended on the owned layer.

## The legal HARD GATE, encoded in the type system

Tokenizing a real-world asset creates a regulated financial instrument in most
jurisdictions, and operating a settlement layer for others' assets very likely
makes the operator a regulated intermediary (see `ffg/README.md` §"RWA is a
separate, regulated, legally-gated instrument"). **Independent qualified legal
review of BOTH the RWA-token classification and the operator-role licensing is
a HARD GATE that no code can satisfy.** This reference encodes that fact:

- `LegalGate` has exactly **one constructible value: `NotObtained`**. There is
  no `Obtained` variant, no bypass, no builder. The type can only ever say the
  review has *not* happened. A doc-test and a unit test pin this: an exhaustive
  `match` with a single arm stops compiling if a second variant is ever added.
- There is **deliberately no `Offer` / `Sell` / `List` operation** in the op
  set. The reference cannot express offering an asset to anyone.

Status of the gate itself: **blocked-on-legal-review** — permanently, until an
actual independent legal review happens outside any codebase.

## One builder among many, on an open rail

The base is an ownerless, permissionless commons. Anyone may build their own
token layer, L2, RWA rails, or finality gadget on it in exactly the same way —
[`BLOCH-PERMISSIONLESS-TOKENS-L2.md`](BLOCH-PERMISSIONLESS-TOKENS-L2.md) is
the open-rail precedent (no gatekeeper, no privilege; Postern is one L2 builder
among many). The sibling `l2/bloch-l2-anchor` crate demonstrates the same
anchoring idiom with a structured wire format (the `L2V0` zero-value-output
envelope); this reference deliberately does **not** duplicate that wire format
and stays **commitment-only** (opaque 32 bytes) — the lightest honest shape.

## Honest limits (keep all of these wherever this reference is described)

- **No proofs.** The chained root is a plain hash chain over the op log. It is
  **NOT a Merkle tree** and supports **no inclusion proofs**, no exclusion
  proofs, no fraud proofs, no validity proofs. Nothing about a root can be
  proven to a third party except by replaying the entire log.
- **No data availability.** The base stores 32 bytes, not the log. If the
  operator withholds the log, the root is unverifiable.
- **No consensus meaning.** Anchored commitments are ordinary tx data; the
  base neither parses nor enforces them, and a malformed or dishonest
  commitment is invisible to base consensus.
- **The base is forgeable.** The Bloch-SIS-PoW base is a mainnet-beta: `k=4`
  trivially-forgeable, `51%`-attackable, unaudited. Even the weak statement "a
  signer asserted this root at height H" can be re-written beneath you.
- **Unaudited, nothing operational.** The crate is a reference scaffold with
  in-process deterministic tests; no service is run, no asset exists, nothing
  is custodied, nothing is offered. Real custody, real asset onboarding, and
  any operated multi-tenant service are **blocked-on-infra / legal-review /
  audit** and out of scope for code.
- **BLCH is worthless and is not a security**; base gas paid to anchor is
  operational spend only, never a value claim.

## Build / test

```sh
cd ffg
cargo test   # default zero-dependency build; kernels never need real-mldsa65
```

Deterministic in-process tests cover: replay determinism (same log ⇒ same
root; reorder/tamper ⇒ different root), RWA invariants (unregistered-asset
transfer, over-balance transfer, double-redeem rejected; freeze blocks
subsequent transfers), the `LegalGate` type surface, BaaS tenant isolation
(one anchor receipt for N tenants; the batch commitment changes iff some
tenant root changed), and the "Postern vanishes" ownerless-base test.
