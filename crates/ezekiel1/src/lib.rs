//! # Ezekiel 1 — the access-layer governance engine for Consiglio
//!
//! > "…and the appearance of the wheels and their work was like unto the colour
//! > of a beryl: and they four had one likeness: and their appearance and their
//! > work was as it were a wheel in the middle of a wheel." — Ezekiel 1:16
//!
//! Ezekiel 1 governs *who may reach what*, per access, fail-closed. It is named
//! for the vision of the wheels: nested access **layers** that may never widen
//! themselves ([`lattice`], *wheels within wheels*); a SHAKE-256 hash-chained
//! **audit trail** that witnesses every grant and denial ([`trail`], *rims full
//! of eyes*); tenant **firmaments** across which no resource or derived signal
//! passes ([`firmament`]); and **per-access evaluation** in which the default is
//! deny ([`eval`], *the spirit in the wheels*).
//!
//! ## Two editions
//!
//! Checked **first** by the [edition gate](edition), fail-closed:
//!
//! - **Personal** — parental control only. A single household, `parent -> child`
//!   levels, no Chinese walls, no tenants, no corporate roles, **no spying**
//!   (inverted control is refused).
//! - **Business** — the full lattice (no-read-up / no-write-down), Brewer-Nash
//!   Chinese walls, and firmament-grade tenant isolation. Runs on the customer's
//!   own infrastructure; there is **no Postern server**.
//!
//! ## The pipeline
//!
//! 1. [`policy`] — parse the strict governance TOML (`deny_unknown_fields`; a
//!    grant without `expires` fails to parse).
//! 2. [`edition`] — the edition gate: refuse any out-of-edition construct.
//! 3. [`lattice`] — build the wheel forest; reject any child that widens past
//!    its parent.
//! 4. [`walls`] — validate Chinese walls (no bypass) and decide Brewer-Nash.
//! 5. [`firmament`] — reject any resource shared across tenants.
//! 6. [`eval`] — the [`Engine`]: validate the policy, anchor a genesis trail
//!    entry, and evaluate each access fail-closed, recording every outcome.
//! 7. [`jobs`] — emit Izbushka manifests (the Yagabona schema) for the expiry
//!    sweep and wall audit that Yagabona runs.
//!
//! ## Honest status — UNAUDITED draft
//!
//! **No third party has reviewed this code.** APIs and the policy/trail formats
//! may change. What is **real**: the edition gate, the no-widening lattice,
//! Brewer-Nash, the fail-closed evaluator, and the hash-chained trail are all
//! implemented and tested here. What is **aspirational**: firmament isolation is
//! enforced *by construction inside a single process* — it is **not** an OS,
//! kernel, or hardware boundary (see [`firmament`] for the full real-vs-
//! aspirational note; it mirrors Yagabona's "userland boundary, not a sandbox"
//! honesty). Sovereignty stays with the data owner; there is no telemetry.

#![forbid(unsafe_code)]

pub mod api;
pub mod edition;
pub mod eval;
pub mod firmament;
pub mod jobs;
pub mod lattice;
pub mod policy;
pub mod trail;
pub mod walls;

/// The `#[wasm_bindgen]` surface — a thin adapter over [`api`] that drives the
/// shipping browser console (`apps/ezekiel1/index.html`) from *this* crate.
/// Present only under `--features wasm` (which pulls in `wasm-bindgen`); the
/// native build and `cargo test` never compile it. See `crates/ezekiel1/wasm/`
/// for the build + WASM↔native parity harness.
#[cfg(feature = "wasm")]
pub mod wasm;

pub use eval::{Action, Decision, Engine, EngineError};
pub use jobs::JobConfig;
pub use lattice::Lattice;
pub use policy::{
    Assignment, Edition, Grant, Layer, Policy, PolicyError, Resource, Subject, Tenant,
};
pub use trail::{verify_chain, ChainError, Entry, Record, Trail, GENESIS};
pub use walls::{ConflictClass, Wall};
