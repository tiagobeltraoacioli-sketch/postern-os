# postern-backup-net

**UNAUDITED wiring crate — REAL confidentiality, not a complete backup system.**

This is the crate that `data/postern-data` (`bloch-data`) repeatedly points to as
"structurally out of this crate's honesty scope": the place the zero-dependency
scaffold's *seams* get plugged into genuine primitives. Spec:
`docs/specs/POSTERN-DATA-FILECOIN-DESIGN.md` §5.

## What it ships today

`PosternSealer` — a concrete implementation of `bloch_data::seal::{Sealer, Opener}`
over the **canonical Postern seal** (`postern-core`):

- **XChaCha20-Poly1305 v2**, key-committing and **context-bound**
  (`postern_core::aead::{seal,open}_with_context`);
- a 32-byte key derived by the memory-hard **Argon2id** KDF
  (`postern_core::kdf`, default 64 MiB / floor 19 MiB tiers), from a passphrase
  plus the public per-backup-set salt/tier the PBP0 `Package` already stores for
  restore.

Unlike `bloch-data`'s in-crate `MockSealer` — a **zero-confidentiality** test
fixture that frames the plaintext verbatim — `PosternSealer` genuinely
**encrypts**: the sealed blob is XChaCha20-Poly1305 ciphertext and the plaintext
never appears in it. `MockSealer` stays only as a contrast test double.

## Acceptance (see `tests/pipeline.rs`)

The end-to-end test runs the whole
`scan → per-file seal → manifest → seal → package → put_car(DirBackend) → get → open`
pipeline with the REAL seal, over the REAL durable on-disk `bloch_data::backend::DirBackend`
(dropped and reopened to simulate a process restart), and asserts:

- **(a)** every restored plaintext is **byte-identical** to the input;
- **(b)** each sealed blob is **real ciphertext** — not the plaintext, and it
  never contains it (genuine confidentiality, unlike `MockSealer`);
- **(c)** restore **fails closed** under a wrong key or a wrong context.

`cargo test` is green (offline, zero network).

## Deliberately OUT OF SCOPE (still slots)

- the **ML-DSA-65‖Falcon-1024** PQ signer that fills `Package::{pk,sig}`;
- the real **SHAKE-256/256** `manifest_root` / per-blob `shake256` (bloch-data's
  `hash` feature carries the real `Shake256Hasher`);
- a **live** Storacha/Lighthouse network client (the test lands on the durable
  on-disk spool, not a live Filecoin provider).

`designed != built != booted.` This crate proves real client-side confidentiality
end-to-end over the durable spool — and nothing about the PQ overlay or the live
network path. It is UNAUDITED and inherits the k=4, low-hashrate, 51%-attackable
Bloch base in full.

Licensed under MIT OR Apache-2.0.
