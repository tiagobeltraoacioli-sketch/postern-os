# bloch-l2-prover

> **SCAFFOLD, UNAUDITED, not a working L2, NOT a zk prover — the MockProver
> proves nothing cryptographically.**

SP1-guest RSP-pattern **skeleton** for the Bloch EVM L2 proving pipeline
(`docs/specs/BLOCH-L2-EVM-DESIGN.md` §3: zk-validity rollup, SP1/FRI,
revm-in-guest per Succinct's RSP). This crate delivers the *types, encodings,
and pipeline shape* with real tests — and honest `// SCAFFOLD:` stubs for the
genuinely large integrations.

## What is REAL and tested here

| Piece | Status |
|---|---|
| `BatchPublicValues` (design §3, field-for-field) | Real. Canonical 256-byte fixed-width LE encoding, decode, round-trip tests, SHAKE-256 domain-separated commitment (the `prev_batch_hash` chain link). |
| `ExecutionWitness` (RSP-shaped: pre-state root, txs, state-witness nodes, bytecodes, ≤256 ancestor headers, deposits) | Real types + canonical length-prefixed ser/de with round-trip, truncation, trailing-byte, and hostile-length tests. |
| `stf(witness) -> Result<BatchPublicValues, StfError>` | Real *placeholder* STF: a deliberately **simplified account-map re-execution** (flat SHAKE-256 state commitment, toy 64-byte transfers, deposit mints, withdrawal burns). **NOT revm, NOT MPT-verified, NOT Ethereum semantics** — it exists so the pipeline is exercisable end-to-end. |
| `MockProver` / `MockProof` | Real plumbing, **zero soundness**: `prove()` re-runs the STF and binds the public values by hash; `verify()` checks the binding. Tests assert accept-on-match, reject-on-tamper, and — deliberately — that the mock is forgeable. |
| Determinism contract | `#![deny(clippy::float_arithmetic)]` via `[lints]`, `BTreeMap`-only state, `no_std`+`alloc` capable (`--no-default-features`), integer-only math. |

## What is honestly STUBBED (`src/sp1_stub.rs`, `// SCAFFOLD:` + `todo!()`)

- The real SP1 **program/script/service** triple (template:
  `crates/coherence-prover` in the Bloch node repo, with its Fly.io L40S GPU
  service).
- riscv32im guest builds (`cargo prove build --docker`, reproducible ELF).
- keccak-256 **MPT witness verification** against `prev_state_root`
  (alloy-trie).
- **revm-in-guest** re-execution (pinned `SpecId::CANCUN`).
- **FRI proof** handling (raw SP1 core/compressed STARK only — the
  Groth16/Plonk curve wrappers are forbidden by the repo's post-quantum rule).
- **vkey pinning** and upgrade envelopes.

## Never say "proof of validity" about the mock

A `MockProof` is a SHAKE-256 hash of public values. Anyone can forge one in a
single hash call (there is a test asserting exactly that). It detects
disagreement about bytes, never fraud. Only a real FRI proof from a real SP1
guest — none of which exists in this crate — could ever carry a validity
claim, and even then only after audits this project has not had.

## Layout / build

Standalone crate with its own empty `[workspace]` (the `crates/bloch-tokens`
pattern), excluded from the product root workspace. One dependency (`sha3`).

```bash
cd l2/bloch-l2-prover
cargo test                        # std
cargo build --no-default-features # no_std + alloc (guest-shaped)
```

License: MIT OR Apache-2.0.
