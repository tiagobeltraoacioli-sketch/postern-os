//! `postern-release` — a `SHA256SUMS` manifest builder plus a detached HYBRID
//! Falcon-1024 + ML-DSA-87 signature over it, for Postern release artifacts.
//!
//! # What this crate is
//!
//! 1. [`manifest`] builds a `SHA256SUMS` manifest over a directory of release
//!    artifacts, matching the repo's existing convention (see
//!    `enterprise/deployment/signing/sign-build.sh`): one
//!    `<sha256-hex>  <relative-path>\n` line per file, paths relative to the
//!    artifacts directory root, sorted under `LC_ALL=C` byte ordering,
//!    `shasum -a 256 -c` / `sha256sum -c` compatible.
//! 2. [`sign`] computes a **detached HYBRID** signature over that manifest:
//!    BOTH a Falcon-1024 leg and an ML-DSA-87 leg are computed over the SAME
//!    domain-separated transcript, and [`sign::verify_manifest`] only
//!    succeeds if **both** legs verify. This is a true AND-of-both hybrid,
//!    not an OR/either-leg check — see the module docs for why, and the
//!    integration tests for proof that corrupting only one leg fails closed.
//! 3. [`tuf`] is a **CORE SCAFFOLD, NOT A WORKING UPDATE CHANNEL** — local,
//!    offline typed models of the four TUF roles, an R2 path-layout
//!    descriptor, and local k-of-n threshold/expiry arithmetic. No online
//!    root rotation, no key-signing ceremony, no metadata fetch, no
//!    delegation. See the module's own docs before using it for anything.
//!
//! # HONESTY — read this before using the output for anything
//!
//! **What a passing [`sign::verify_manifest`] proves:** the manifest bytes
//! (and therefore every artifact hash it lists) are byte-identical to what
//! the holder of BOTH the Falcon-1024 secret key and the ML-DSA-87 secret key
//! signed. That is **origin + integrity**, full stop.
//!
//! **What it does NOT prove:**
//! - **Not attestation.** It says nothing about the build environment, the
//!   toolchain, or that the artifact was built the way anyone claims it was.
//! - **Not reproducibility.** It does not mean a third party can rebuild the
//!   same bytes from source. Reproducible builds are an orthogonal, unstarted
//!   effort.
//! - **Not an audit / security sign-off.** A valid signature is not a claim
//!   that the artifact is safe, correct, or free of vulnerabilities.
//!
//! **This COMPLEMENTS, and does NOT replace,** the repo's existing
//! `minisign` (Ed25519) signature over the same `SHA256SUMS` convention
//! (`enterprise/deployment/signing/{sign,verify}-build.sh`,
//! `pmos-overlay`'s publish flow). Ship and verify BOTH. A release is not
//! "PQ-signed instead of classically-signed" — it is signed with both, and a
//! consumer that only checks one has only checked one.
//!
//! **UNAUDITED, both legs:**
//! - [`ml-dsa`](https://docs.rs/ml-dsa) is a **pre-1.0** (`0.1.x`) pure-Rust
//!   FIPS 204 implementation from RustCrypto. It has not had an independent
//!   security audit as of this crate's writing.
//! - [`pqcrypto-falcon`](https://docs.rs/pqcrypto-falcon) wraps the
//!   `clean` C reference implementation from
//!   [PQClean](https://github.com/pqclean/pqclean/), which is itself
//!   **unaudited** upstream C, called through Rust FFI bindings that are
//!   also unaudited as a binding layer.
//!
//! Neither leg being "the NIST-standardized algorithm" (ML-DSA is FIPS
//! 204-final; Falcon is a NIST PQC alternate, not yet a FIPS number) changes
//! either of those UNAUDITED facts. Treat both as experimental.
//!
//! **Keys are operator-held.** This crate generates keys only in memory
//! (`sign::KeyPair::generate`) or from bytes an operator supplies; it never
//! writes a production private key into this repository. Any `dev`/`sample`
//! keys produced by the CLI's `keygen` subcommand or referenced in this
//! crate's own tests exist ONLY to exercise the sign/verify flow in CI and
//! MUST NOT be used, and are not fit, to sign a real release.
//!
//! **Licensing:** every dependency this crate pulls in the DEFAULT build
//! (`ml-dsa`, `pqcrypto-falcon`, `pqcrypto-traits`, `sha2`, `thiserror`,
//! `zeroize`) is Apache-2.0 and/or MIT. The `tuf-tough` feature (see
//! [`tuf::tough_link`]) additionally pulls in `tough` (MIT OR Apache-2.0),
//! `jiff` (Unlicense OR MIT), and `url` (MIT OR Apache-2.0) — all
//! permissive; their own transitive dependency trees checked clean of
//! GPL/AGPL/LGPL-only terms as of this writing (`cargo license`). No
//! copyleft (GPL/AGPL/LGPL) in this crate's dependency tree either way.

pub mod manifest;
pub mod sign;
pub mod tuf;

pub use manifest::{build_manifest, write_manifest, ManifestError, MANIFEST_NAME};
pub use sign::{sign_manifest, verify_manifest, HybridSignature, KeyPair, PublicKeyBundle, SignError, VerifyError};
