<!--
SPDX-License-Identifier: MIT OR Apache-2.0
WalletCore on-device validation (B5/B3 front, dev M-apk). Status: native-proven,
on-target UNRUN. Non-attestable tier context; software keystore; coin worthless.
-->

# WalletCore on-device (B3)

`mobile/core` (`bloch-mobile`) is the **pure** wallet engine — no network, no
disk, no FFI of its own — that both the desktop app and `crates/postern-sdk`
(the single shipped UniFFI surface) fold in. B3 asks that this engine **run on
target** and that its golden byte-identity hold there, exactly as it does on the
node.

## Proven on this host (2026-07-12) — native

`cargo test` in this crate is **green: 6/6**, including:

- `golden_byte_identity_asserts_equal_to_dev_a_canonical_tuple` — assert-equals
  Dev-A's **published canonical tuple** for `GOLDEN_SEED = [0x11; 32]`
  (mainnet `bloch1q7b003a342f1529f4943e52181c661b0e34c96d02b71f8b78`,
  testnet `bloch1t7b…`). This is a live assert (never `#[ignore]`); it passes
  because the `bloch-crypto` dep is pinned to the merged rev
  `dd8df3526518ba792057708a6aa0efd5a91d8e40`, grep-confirmed identical across
  every coordinated `Cargo.toml` in the tree. The literals are Dev-A's values,
  **not re-blessed**.
- `sign_tx_hex_produces_consensus_verifiable_signature` — a signed tx parses back
  and `parse_script_sig` → `verify` passes under the wallet's chain-id domain
  (byte-compatible with the node validator).
- `diversified_address_rotation`, `mnemonic_roundtrip_is_deterministic`,
  `sign_produces_verifiable_hybrid_signature`, `rpc_request_shape`.

That proves the **engine** (keygen, address derivation, Falcon‖ML-DSA hybrid
signing, tx sighash, diversified addresses) on this host. It is **not** an
on-device run.

## On-target validation (UNRUN — the actual B3 gate)

The engine reaches the phone two ways; both need a booted aarch64 target
(dev-4's image boot, B4) or an existing pmOS device:

1. **Via the published `postern-wallet` apk.** That CLI is `bloch-crypto`'s
   `wallet::cli` built from the *same* rev this crate pins, so the address it
   derives for a known seed **must equal** the golden tuple above. The on-device
   cross-check lives in `../pmos-overlay/DEVICE-VALIDATION.md §2.b`:
   `postern-wallet` on-device must reproduce `bloch1t7b…` for the golden seed.
   Byte-identity engine (this crate) ⟷ CLI (the apk) ⟷ node — one derivation.
2. **Via `postern-sdk` on the aarch64 image.** Build this crate for
   `aarch64-unknown-linux-musl` (or run the SDK's test harness inside the booted
   image) and run the same golden assert on-target. DoD: the golden test passes
   **on the device**, not just on the build host.

**On-target harness (record as evidence, per DEVICE-VALIDATION.md §4):**

```sh
# inside the booted aarch64 image (or an aarch64 pmOS device):
cargo test -p bloch-mobile golden_byte_identity   # if a Rust toolchain is present, OR
postern-wallet address --seed-hex 1111...11 --testnet   # must print bloch1t7b…  (same bytes)
```

## Honesty

- **Not attested.** A passing on-device test proves the engine *runs*; it says
  nothing about *what it was built from* (no Nix closure, no measured boot here).
- **Software keystore.** On pmOS the durable secret is a **software** keystore —
  no StrongBox / Secure Enclave. The `Drop` zeroize here wipes the in-RAM copy;
  it is defense-in-depth, not hardware backing. Never claim hardware-backed keys
  on this tier.
- **Byte-identity is a guardrail, not a security claim.** It ensures the mobile
  wallet and the node agree on addresses/signatures. UNAUDITED, coin worthless.
