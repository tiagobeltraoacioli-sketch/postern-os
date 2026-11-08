//! The **rims full of eyes** — Ezekiel 1's append-only, hash-chained audit trail.
//!
//! > "…their rings were full of eyes round about…" — Ezekiel 1:18
//!
//! Every governance event — a grant, a denial, a policy change, a lowered wall —
//! is one [`Entry`]; each commits to the previous entry's hash, so history can be
//! *extended* but never silently rewritten.
//!
//! # A thin adapter over `postern-trail`
//!
//! The earlier follow-up note is now resolved: the mechanism — canonical JSON,
//! the SHAKE-256 chain, `verify_chain`, `fsync`-per-append — lives in the shared
//! [`postern_trail`] crate, which `yagabona` (the "glowing skull") uses too.
//! This module only defines Ezekiel 1's **content fields** and re-exports the
//! public names the rest of the crate expects. The two trails now *cannot* drift
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
//! preimage = canonical_json({ actor, decision, event, reason, resource,
//!                             subject, ts, prev_hash, v })         // no `hash`
//! hash     = SHAKE-256( prev_hash_bytes ‖ preimage_bytes )        // 32 bytes, hex
//! ```
//!
//! The first entry's `prev_hash` is the literal [`GENESIS`]; `v` is the pinned
//! schema version. See the [`postern_trail`] crate docs for the full canonical
//! form.
//!
//! # Honesty
//!
//! This is **tamper-evident, not tamper-proof.** A data owner can rewrite the
//! whole file and recompute every hash; what [`verify_chain`] guarantees is that
//! a *partial* edit is detected. **UNAUDITED draft.**

use serde::{Deserialize, Serialize};

pub use postern_trail::{verify_chain, verify_chain_to_head, ChainError, GENESIS};

/// The content of an Ezekiel 1 trail entry (every field except the chain's
/// `prev_hash`/`hash`/`v`, which the shared trail assigns).
///
/// Kept named `Record` for backwards compatibility with existing call sites,
/// which construct it with field syntax and hand it to [`Trail::append`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// RFC 3339 timestamp of the event.
    pub ts: String,
    /// Who caused the event (an owner id, a subject, or `"engine"`).
    pub actor: String,
    /// What kind of event: `"policy-loaded"`, `"grant"`, `"deny"`, `"allow"`,
    /// `"policy-change"`, `"wall-lowered"`.
    pub event: String,
    /// The subject the event concerns (or `"-"`).
    pub subject: String,
    /// The resource the event concerns (or `"-"`).
    pub resource: String,
    /// The decision reached: `"allow"`, `"deny"`, or `"n/a"`.
    pub decision: String,
    /// Human-readable reason (the denial reason, the change summary, …).
    pub reason: String,
}

/// A finalized trail entry (one JSONL line): the content above plus the chain's
/// `v`/`prev_hash`/`hash`. Access `.prev_hash` / `.hash` on this; the content
/// fields live under `.content`.
pub type Entry = postern_trail::Record<Record>;

/// An append-only, hash-chained trail writer for Ezekiel 1 content.
pub type Trail = postern_trail::Trail<Record>;

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(event: &str, decision: &str) -> Record {
        Record {
            ts: "2026-07-11T02:30:00Z".to_string(),
            actor: "engine".to_string(),
            event: event.to_string(),
            subject: "alice".to_string(),
            resource: "finance/ledger".to_string(),
            decision: decision.to_string(),
            reason: "-".to_string(),
        }
    }

    #[test]
    fn append_links_to_genesis_then_previous_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.jsonl");
        let mut trail = Trail::open(&path).unwrap();
        assert_eq!(trail.head(), GENESIS);

        let first = trail.append(rec("allow", "allow")).unwrap();
        assert_eq!(first.prev_hash, GENESIS);
        assert_eq!(first.hash.len(), 64);

        let second = trail.append(rec("deny", "deny")).unwrap();
        assert_eq!(second.prev_hash, first.hash);

        assert_eq!(verify_chain(&path).unwrap(), 2);
    }

    #[test]
    fn pinned_head_catches_a_dropped_governance_entry() {
        // A truncated governance trail is a valid shorter chain; only a pinned
        // head reveals that the last decision was dropped.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.jsonl");
        let mut trail = Trail::open(&path).unwrap();
        trail.append(rec("allow", "allow")).unwrap();
        let head = trail.append(rec("deny", "deny")).unwrap().hash;

        // Drop the last line (the deny) — plain verify still passes at length 1.
        let kept: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .take(1)
            .map(str::to_string)
            .collect();
        std::fs::write(&path, kept.join("\n") + "\n").unwrap();
        assert_eq!(verify_chain(&path).unwrap(), 1);

        // Pinning the real head flags the truncation.
        assert!(matches!(
            verify_chain_to_head(&path, &head).unwrap_err(),
            ChainError::HeadMismatch { .. }
        ));
    }
}
