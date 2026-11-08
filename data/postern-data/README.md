<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# bloch-data

**SCAFFOLD, UNAUDITED, NOT A WORKING BACKUP SYSTEM.** Offline, zero-dependency
skeleton for the Postern → Filecoin *user-backup* path: the **`DATA0`
zero-value Bloch anchor** codec, the **`PBM0` backup-manifest** codec, and the
two seams (`StorageBackend`, `Sealer`/`Opener`) where the untrusted world
begins. Spec: `docs/specs/POSTERN-DATA-FILECOIN-DESIGN.md`. Companion idiom:
`l2/bloch-l2-anchor` (the L2V0/TKV0 anchor rail this reuses).

Private user data is sealed **client-side** with the existing Postern seal
*before* it leaves the sealed base; Filecoin only ever sees ciphertext.
Integrity/authenticity is a post-quantum overlay — a SHAKE-256 manifest root,
signed with Bloch's ML-DSA-65‖Falcon-1024 hybrid, anchored to the ownerless
Bloch base as a zero-value `DATA0` envelope — sitting **on top of** Filecoin's
non-PQ sha2-256 CIDs.

## Honesty box (non-negotiable)

- **`designed` ≠ `built` ≠ `booted`.** This crate is a first-iteration
  compiling scaffold of the *offline, trust-bearing* pipeline plus its seams.
  Nothing here uploads, seals, hashes, or signs anything for real, and nothing
  means "your files are backed up".
- **The DEFAULT build is ZERO dependencies, ZERO network, ZERO live crypto.**
  Built with no features it does **not** hash content (the SHAKE-256 manifest
  root is an opaque `[u8; 32]` *slot*), does **not** run the PQ signer (the
  ML-DSA/Falcon signature is an opaque `Vec<u8>` *slot*), does **not** encrypt
  (confidentiality is the Postern seal, reached only through the
  `Sealer`/`Opener` traits; the in-crate `MockSealer` is a **test fixture with
  zero confidentiality** — it does not encrypt), and has **no network client**.
  Two **opt-in, OFF-by-default, UNAUDITED** cargo features cross specific slots
  into their real primitives (see [Optional features](#optional-features-live--hash)):
  `hash` compiles the real `SHAKE-256/256` `Shake256Hasher` (the ONLY feature
  that pulls a dependency — `sha3`) and its `SHA3-256(pk)` `signer_commit`;
  `live` compiles the real Lighthouse `LiveBackend` network client (still
  zero-dep — a hand-rolled HTTP/1.1 client that needs a local TLS-terminating
  proxy to reach the HTTPS hosts). The PQ signer and the Postern-seal adapter
  stay **out of this crate's scope** (later, in `postern-backup-net`). Enabling
  either feature does **not** make this a working backup system, and the earlier
  framing of "no runtime flag can turn crypto on" no longer holds — the honesty
  gate is now the explicit, labelled feature opt-in, not the absence of one.
- **ZERO consensus change; Bloch nodes never parse this.** The `DATA0`
  envelope rides the `script_pubkey` of a zero-value output of an
  already-valid Bloch transaction. A malformed envelope is a layer no-op and
  never invalidates the carrying transaction.
- **Bloch stays ownerless.** Anchoring is permissionless — any fee-payer can
  write `DATA0` bytes — so a decoded envelope is only a **claim** until a
  reader recomputes the root and verifies the PQ signature (which this crate
  does not do). The base is `k=4`, low-hashrate, 51%-attackable, and
  unaudited; anything anchored inherits that in full.

## `DATA0` anchor wire format (fixed 141 bytes)

`script_pubkey` of a **zero-value** output; all integers little-endian; strict
decode (exact magic, exact version, exact length); malformed ⇒ no-op.

| offset | size | field |
|---:|---:|---|
| 0 | 4 | magic ASCII `"DAT0"` (`44 41 54 30`) |
| 4 | 1 | version `u8` = `0x00` |
| 5 | 32 | `vault_id` (binds the anchor chain to one backup signer) |
| 37 | 8 | `manifest_index` `u64` LE (strictly increasing per vault) |
| 45 | 32 | `prev_root` (previous anchor's `new_root`; `[0;32]` at genesis) |
| 77 | 32 | `new_root` (the signed SHAKE-256 manifest root — opaque slot) |
| 109 | 32 | `da_commitment` (off-chain manifest locator/commitment) |

## `PBM0` manifest wire format

Length-prefixed, bounds-checked, re-encodes byte-identically:

```text
magic "PBM0" (4) ‖ version 0x00 (1) ‖ vault_id [32] ‖ entry_count u32 LE
entries[]: cid_len u16 LE ‖ cid[cid_len] ‖ sealed_len u64 LE
manifest_root [32]   (opaque slot — SHAKE-256, computed elsewhere)
sig_len u32 LE ‖ signature[sig_len]   (opaque slot — ML-DSA/Falcon, signed elsewhere)
```

Each `cid` is a provider-reported **locator only** (zero integrity weight); a
fetched chunk must be re-hashed against an out-of-band SHAKE digest before use.

## What is real vs stubbed

- **REAL + TESTED** — `src/anchor.rs`: strict `DATA0` encode/decode with typed
  errors (never panics), zero-value extraction (`extract_anchor`,
  first-wins), and the pure `link` chain check. `src/manifest.rs`: strict
  `PBM0` codec, adversarial length prefixes fail bounds checks rather than
  over-allocating. `tests/vectors.rs` pins both layouts with hand-written hex
  golden vectors and runs an offline end-to-end pipeline smoke test.
- **SEAM + test double** — `src/backend.rs`: the `StorageBackend` trait
  (`put_car` / `get` / `deal_status`), the in-memory `MockBackend` with
  fault injection, and `LiveBackend` — a `todo!()` SCAFFOLD stub in the
  default build, replaced by the **real Lighthouse client** (`src/live.rs`)
  under `--features live`. `src/seal.rs`: the `Sealer`/`Opener` traits the
  real `postern-core` AEAD plugs into, and the zero-confidentiality
  `MockSealer` for failure-mode tests. `src/hash.rs`: the `Hasher` seam and
  its zero-collision-resistance `MockHasher` default double, plus the **real
  `Shake256Hasher`** (`SHAKE-256/256` + `SHA3-256(pk)` `signer_commit`) under
  `--features hash`. This crate never *re-implements* crypto — under `hash` it
  adapts the audited `sha3` crate.

## Optional features (`live` + `hash`)

Both are **UNAUDITED**, **OFF by default**, and gated so the default build
stays zero-dep and network-incapable. Enabling them makes the corresponding
primitive real but does **not** produce a working backup system (sealing and
the ML-DSA/Falcon PQ signer remain out of this crate's scope):

| feature | flips | what ships | deps | caveat |
|---|---|---|---|---|
| `hash` | `SHAKE-256` slot | `hash::Shake256Hasher` — real `SHAKE-256/256(domain‖bytes)` `manifest_root`/`blob_digest` and real `SHA3-256(pk)` `signer_commit`; KAT-tested (`tests/hash_kat.rs`) | `sha3` (the ONLY dependency any feature pulls) | UNAUDITED; a real root/digest, not a full backup |
| `live` | `LiveBackend` stub | `live::LiveBackend` — the real Lighthouse hosted-provider client, re-exported as `backend::LiveBackend` | none (hand-rolled HTTP/1.1 over `std::net::TcpStream`) | UNAUDITED; **needs a local TLS-terminating proxy** (`stunnel`/`socat` to `node.lighthouse.storage:443`) + `LIGHTHOUSE_*_URL` overrides — `https://` targets are rejected with a typed error. Ciphertext-only: data is Postern-sealed before it reaches any backend, and the returned CID is a provider locator with zero integrity weight. |

Still out of scope for this crate (later, in `postern-backup-net`): the
ML-DSA-65‖Falcon-1024 signer, the Postern-seal AEAD adapter, and the
Storacha/Tor transport rails.

## Build

Standalone crate with its own empty `[workspace]`. The default build is
zero-dependency and offline-buildable; the two opt-in features add the real
primitives (only `hash` pulls a dependency, `sha3`):

```sh
cd data/postern-data
cargo test                       # default: zero-dep, offline, MockHasher + stub LiveBackend
cargo test --features hash       # + real SHAKE-256 Shake256Hasher (KATs)
cargo test --features live       # + real Lighthouse LiveBackend (offline unit tests; live path needs a TLS proxy)
cargo test --features live,hash  # both real primitives together
```

### Live Lighthouse round-trip (operator-gated)

`src/live.rs` carries `real_lighthouse_smoke_if_token_present`, an `#[ignore]`d
test that performs a genuine upload → CID → re-fetch against the real provider.
It is opt-in so `cargo test --features live` stays offline. To run it you supply
your own free key and, since no TLS is linked in-crate, a local TLS proxy:

```sh
export LIGHTHOUSE_API_KEY=<free key from lighthouse.storage>
# front the HTTPS hosts with a plaintext local proxy (stunnel/socat):
#   127.0.0.1:8443 -> node.lighthouse.storage:443
#   127.0.0.1:8444 -> gateway.lighthouse.storage:443
export LIGHTHOUSE_UPLOAD_URL=http://127.0.0.1:8443/api/v0/add
export LIGHTHOUSE_GATEWAY_URL=http://127.0.0.1:8444/ipfs
cargo test --features live real_lighthouse_smoke_if_token_present -- --nocapture --ignored
```

Honest by construction: with no key (or the endpoints still the unreachable
default HTTPS hosts) the `--ignored` run is a documented **no-op** that prints
why and passes. This crate never fabricates a token or a CID — a real PASS only
happens against a real provider.

## License

MIT OR Apache-2.0.
