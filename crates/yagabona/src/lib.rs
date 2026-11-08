//! Yagabona — the privacy-first scheduled-task **agent daemon** for Postern OS.
//!
//! Yagabona (Latin *bona*, "the good one") is the benevolent reading of
//! the Slavic witch of folklore: in Propp's morphology she is the **donor** — the threshold
//! guardian who tests whoever approaches, rewards diligence and honesty, and
//! punishes overreach. She does not work for the cloud. She works for the owner
//! of the machine and no one else.
//!
//! A task only runs if the user has *spoken the ritual formula*: an explicit,
//! scoped, expiring capability grant declared in an **Izbushka manifest** (the
//! hut on chicken legs turns its door only to those who ask correctly). No
//! formula, no door.
//!
//! # The pipeline
//!
//! 1. [`manifest`] — parse the Izbushka TOML into typed structs.
//! 2. [`threshold`] — the **Threshold Test** ([`validate`]): fail-closed
//!    validation that yields a [`Grant`] or a [`Refusal`]. Nothing executes on
//!    a refusal.
//! 3. [`fsboundary`] — a [`ScopedFs`] guard that checks every path against the
//!    grant before opening a file (the runtime boundary).
//! 4. [`trail`] — the *glowing skull*: an append-only, SHAKE-256 hash-chained
//!    JSONL audit trail that can be [`verify_chain`]ed and detects any rewrite.
//! 5. [`scheduler`] — parse the schedule, and a tick loop that re-checks
//!    expiry/revocation and runs the (stubbed) [`Task`] inside its grant.
//!
//! # Honest status
//!
//! **UNAUDITED. Draft.** The filesystem boundary in [`fsboundary`] is a
//! *userland* check — it validates paths against the grant before opening them.
//! It is **not** an OS sandbox. True kernel-enforced confinement (Landlock,
//! seccomp-bpf, the macOS sandbox) is the follow-up and is not implemented here.
//! Task execution is a safe stub/trait; this crate never spawns arbitrary code.
//!
//! # Zero telemetry
//!
//! No analytics, no crash reporting, no phoning home. Consistent with the "no
//! Postern server" thesis — Yagabona introduces no server-side exception.

#![forbid(unsafe_code)]

pub mod fsboundary;
pub mod manifest;
pub mod scheduler;
pub mod threshold;
pub mod trail;

pub use fsboundary::{FsError, ScopedFs};
pub use manifest::{Capabilities, Manifest, ManifestError, Network, Ritual, Task as TaskSpec};
pub use scheduler::{PollResult, Runner, Schedule, ScheduleError, Task, TaskError};
pub use threshold::{validate, validate_at, Grant, Refusal, RefusalReason};
pub use trail::{verify_chain, ChainError, Entry, Record, Trail};
