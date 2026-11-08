// SPDX-License-Identifier: MIT OR Apache-2.0
//! Library-target facade over `bloch-desktop`'s Tauri backend — exists ONLY
//! so `tests/*.rs` integration tests (compiled by Cargo as separate crates)
//! can import and directly exercise backend functions without spinning up a
//! real Tauri app/window. See Cargo.toml's `[lib]` comment and `main.rs`'s
//! own `mod` declarations for the other (bin-side) half of this deliberate
//! two-target split.
//!
//! Re-exported here (each with its own `tests/*.rs` driver):
//! - `terem` — the QEMU/QMP guest-lifecycle functions (tests/terem_lifecycle.rs).
//! - `hygiene` — the pure `scrub`/`scrub_b64` functions behind the
//!   `hygiene_scrub` command (tests/hygiene_scrub.rs).
//! - `quarantine` — the pure `rebuild`/`rebuild_b64` functions behind the
//!   `quarantine_rebuild` command (postern-quarantine: image pixel round-trip
//!   → clean PNG, PDF pure-Rust `hayro` render → flat metadata-free PDF; the
//!   MIRROR of hygiene, "receive" side; fails closed on office/unknown magic;
//!   render is IN-PROCESS with NO OS-level containment) (tests/quarantine.rs).
//! - `vault` — the pure on-disk encode/decode, the status-JSON builder (with
//!   its mandatory "not a TEE until real hardware" honesty field and, in the
//!   `keychain` object, the mandatory "SOFTWARE convenience, not hardware
//!   protection" keychain honesty field), the RFC 6238 TOTP core behind
//!   `vault_totp_code`, and — behind the opt-in `vault-keychain` feature —
//!   the pure `keychain_*_impl` / `unlock_keychain_impl` cores, written
//!   against `&mut dyn KeyStore` so the tests drive them with postern-vault's
//!   RAM-only `InMemoryKeyStore` (no OS keychain in CI) (tests/vault_core.rs).
//! - `courier` — the pure envelope seal/open cores (postern-courier hybrid PQ
//!   seal; mock-transport tested only, no live-anonymity claim) behind the
//!   `courier_*` commands (tests/courier_core.rs).
//! - `keys` — the pure passkey `*_impl` cores (postern-keys ES256 software
//!   authenticator — RAM-only, "not a TEE until real hardware") behind the
//!   `keys_*` commands (tests/keys_core.rs). Pulls in `sha256` (the
//!   dependency-free digest also used by the bin target's integrity pin).
//! - `vestnik` — the pure custody cores (vault-custodied courier recipient
//!   secret + opaque sealed SavedSession blob store/load/open; fail-closed
//!   on locked vault / foreign secret / tampered blob / missing blob) behind
//!   the `vestnik_*` custody commands (tests/vestnik_custody.rs). Custody
//!   only in a default build; the client layer is `vestnik_client` below.
//! - `vestnik_client` — the matrix CLIENT layer behind the opt-in
//!   `vestnik-matrix` cargo feature (OFF by default; the `vault-keychain`
//!   pattern): pure login/seal/restore/rooms/tier-gated-send cores over
//!   postern-messenger's MatrixMessenger, driven offline by
//!   tests/vestnik_client.rs against matrix-sdk's loopback MatrixMockServer
//!   (required-features gated), plus the feature-off "not built with matrix
//!   support" stub shape (tests/vestnik_client_stub.rs). A homeserver is
//!   contacted ONLY on user action — never in CI, never at startup.
//!
//! Nothing else in this app (wallet, pairing) is re-exported here — this
//! crate is scoped to those modules' test surfaces, not a general library.

pub mod courier;
pub mod hygiene;
pub mod keys;
pub mod quarantine;
pub mod sha256;
pub mod terem;
pub mod vault;
pub mod vestnik;
pub mod vestnik_client;
