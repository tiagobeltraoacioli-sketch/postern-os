//! The **glowing skull** — Yagabona's append-only, hash-chained audit trail.
//!
//! One JSONL file per task. Every line commits to the previous line's hash, so
//! history can be *extended* but never silently rewritten.
//!
//! # A thin adapter over `postern-trail`
//!
//! The mechanism itself — canonical JSON, the SHAKE-256 chain, `verify_chain`,
//! `fsync`-per-append — lives in the shared [`postern_trail`] crate, which
//! `ezekiel1` (the "rims full of eyes") uses too. This module only defines
//! Yagabona's **content fields** and re-exports the public names the rest of the
//! crate expects. Extracting the mechanism means the two trails can never drift
//! into incompatible canonical forms.
//!
//! * [`Trail`] = [`postern_trail::Trail`]`<`[`Record`]`>`
//! * [`Entry`] = a finalized [`postern_trail::Record`]`<`[`Record`]`>`
//! * [`Record`] = the content of a new entry (before the chain assigns
//!   `prev_hash`/`hash`)
//! * [`verify_chain`], [`ChainError`], [`GENESIS`] come straight from the shared
//!   crate.
//!
//! # The chain
//!
//! ```text
//! preimage = canonical_json({ action, network_used, paths_touched,
//!                             result, task, ts, prev_hash, v })   // no `hash`
//! hash     = SHAKE-256( prev_hash_bytes ‖ preimage_bytes )        // 32 bytes, hex
//! ```
//!
//! The first entry's `prev_hash` is the literal [`GENESIS`]; `v` is the pinned
//! schema version. See the [`postern_trail`] crate docs for the full canonical
//! form.
//!
//! # Honesty
//!
//! This is **tamper-evident, not tamper-proof.** The owner of the machine can
//! rewrite the whole file and recompute every hash; what [`verify_chain`]
//! guarantees is that a *partial* edit is detected. **UNAUDITED draft.**

use serde::{Deserialize, Serialize};

pub use postern_trail::{verify_chain, verify_chain_to_head, ChainError, GENESIS};

/// The content of a Yagabona trail entry (every field except the chain's
/// `prev_hash`/`hash`/`v`, which the shared trail assigns).
///
/// Kept named `Record` for backwards compatibility with existing call sites,
/// which construct it with field syntax and hand it to [`Trail::append`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// RFC 3339 timestamp of the action.
    pub ts: String,
    /// Task name this entry belongs to.
    pub task: String,
    /// What happened, e.g. `"run"`, `"refused"`, `"expired"`.
    pub action: String,
    /// Concrete paths touched by the action.
    pub paths_touched: Vec<String>,
    /// Network destination actually used (`"none"` or `"api.anthropic.com"`).
    pub network_used: String,
    /// Outcome, e.g. `"ok"` or an error summary.
    pub result: String,
}

/// A finalized trail entry (one JSONL line): the content above plus the chain's
/// `v`/`prev_hash`/`hash`. Access `.prev_hash` / `.hash` on this; the content
/// fields live under `.content`.
pub type Entry = postern_trail::Record<Record>;

/// An append-only, hash-chained trail writer for Yagabona content.
pub type Trail = postern_trail::Trail<Record>;

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(action: &str) -> Record {
        Record {
            ts: "2026-07-11T02:30:00Z".to_string(),
            task: "nightly-notes-index".to_string(),
            action: action.to_string(),
            paths_touched: vec!["index/db".to_string()],
            network_used: "none".to_string(),
            result: "ok".to_string(),
        }
    }

    #[test]
    fn append_links_to_genesis_then_previous_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.jsonl");
        let mut trail = Trail::open(&path).unwrap();
        assert_eq!(trail.head(), GENESIS);

        let first = trail.append(rec("run")).unwrap();
        assert_eq!(first.prev_hash, GENESIS);
        assert_eq!(first.hash.len(), 64);

        let second = trail.append(rec("run")).unwrap();
        assert_eq!(second.prev_hash, first.hash);

        assert_eq!(verify_chain(&path).unwrap(), 2);
    }
}
