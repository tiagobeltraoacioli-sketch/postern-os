//! Append-only backup-set evidence log + the vocabulary-gated render.
//!
//! Spec: `docs/specs/POSTERN-DATA-FILECOIN-DESIGN.md` §6 ("Vocabulary gates")
//! and §7 (the phased build plan — the journal persists under a spool dir and
//! is the resume point for the fail-safe upload ordering). This module is the
//! offline, zero-dep skeleton of that log.
//!
//! HONESTY (non-negotiable, this module is where it bites):
//!
//! * The **four journal states are the ONLY permitted claims** the design
//!   allows a CLI/UI to render, each requiring its named evidence:
//!   `sealed locally` → `uploaded (provider ack, CID …)` →
//!   `anchored (tx …, unconfirmed / confirmed-depth-N on a k=4 base)` →
//!   `deal observed (dealId …, endEpoch …)`. The words **"secured"**,
//!   **"backed up"** (as a completed state), and **"permanent"** are FORBIDDEN
//!   and never appear in [`Journal::render`]'s output —
//!   [`Journal::render_is_clean`] and the tests assert this mechanically.
//! * Every rendered anchor line carries the verbatim caveat
//!   [`ANCHOR_CAVEAT`]: *"anchored to Bloch (k=4, 51%-attackable); anchor =
//!   ordering/tamper-evidence claim, not finality."* The base is k=4,
//!   low-hashrate, 51%-attackable, unaudited; an anchor is an ordering /
//!   tamper-evidence **claim**, never finality.
//! * This log carries **no crypto and does no verification**. Roots,
//!   signatures, txids and CIDs are opaque bytes recorded verbatim from the
//!   caller; the journal never recomputes a root, checks a signature, or
//!   contacts a provider. A recorded [`Evidence::Uploaded`] means the *caller*
//!   observed a provider ack — the offline crate has no network client and so
//!   claims nothing about the network itself.
//! * The log is **append-only** and its stage order is enforced (§7's
//!   fail-safe ordering: files sealed first, package uploaded second, anchor
//!   **only after** the provider acks, deal-observation last). A record whose
//!   stage would skip a prerequisite is rejected with a typed
//!   [`JournalError`]; existing records are never mutated or removed.
//!
//! The offline crate makes no network claims because it contains no network
//! client. designed != built != booted.

use crate::backend::{Cid, DealInfo};

/// The verbatim anchor caveat the design (§6) mandates on every rendered
/// anchor line. Printed byte-for-byte; do not paraphrase.
pub const ANCHOR_CAVEAT: &str =
    "anchored to Bloch (k=4, 51%-attackable); anchor = ordering/tamper-evidence claim, not finality.";

/// Words the render is forbidden (§6) to ever emit as a completed-state
/// claim. [`Journal::render_is_clean`] scans the rendered output for these
/// (case-insensitively) as a mechanical gate.
pub const FORBIDDEN_CLAIMS: [&str; 3] = ["secured", "backed up", "permanent"];

/// One evidence stage in the fail-safe backup pipeline. Ordering is total and
/// is what [`Journal::append`] enforces: a record may only be appended once
/// every earlier stage has at least one record (files first, package second,
/// anchor only after the provider acks, deal-observation last).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    /// Sealed locally on the trusted base — nothing has left it yet.
    Sealed = 0,
    /// The package was uploaded and the provider acked a CID (hot layer only).
    Uploaded = 1,
    /// The DATA0 anchor was written to a Bloch block (a *claim*, not finality).
    Anchored = 2,
    /// A Filecoin deal was observed for the stored CID.
    DealObserved = 3,
}

impl Stage {
    /// The immediately-preceding stage a record of this stage requires, or
    /// `None` for the first stage ([`Stage::Sealed`], which needs nothing).
    fn prerequisite(self) -> Option<Stage> {
        match self {
            Stage::Sealed => None,
            Stage::Uploaded => Some(Stage::Sealed),
            Stage::Anchored => Some(Stage::Uploaded),
            Stage::DealObserved => Some(Stage::Anchored),
        }
    }
}

/// Depth of a recorded anchor under the reader's view at the time it was
/// journaled. `Unconfirmed` = seen only in the mempool / not yet in a block
/// the reader accepts; `ConfirmedDepth(n)` = in a block `n` deep. On a k=4
/// base **no depth is finality** — this is a claim, never a guarantee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorDepth {
    /// Broadcast but not yet in a block the reader has accepted.
    Unconfirmed,
    /// In a Bloch block `depth` blocks deep (`0` = tip block).
    ConfirmedDepth(u64),
}

/// One evidence record's payload — exactly one of the four permitted states,
/// each carrying only its named evidence. All bytes are opaque and recorded
/// verbatim; this crate neither produces nor verifies them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// Sealed locally: the backup-set's manifest root (opaque 32-byte slot,
    /// produced outside this crate) and the number of sealed entries.
    Sealed {
        /// Opaque SHAKE-256 manifest-root slot (never computed here).
        manifest_root: [u8; 32],
        /// Number of sealed blobs in the set.
        entry_count: u64,
    },
    /// Uploaded: the provider-reported CID (a LOCATOR, zero integrity weight),
    /// its reported size, an optional provider piece-ref, and the caller's
    /// observation time.
    Uploaded {
        /// Provider-reported content locator (untrusted).
        cid: Cid,
        /// Provider-reported object size in bytes.
        size: u64,
        /// Provider piece-CID-v2 ref, if the provider returns one.
        provider_ref: Option<Vec<u8>>,
        /// Unix time the caller observed the ack (supplied by the caller;
        /// this crate has no clock policy).
        observed_unix: u64,
    },
    /// Anchored: the carrying Bloch txid, the DATA0 `sequence`, and the depth
    /// under the reader's view. An anchor is an ordering / tamper-evidence
    /// **claim** on a k=4 base — never finality (see [`ANCHOR_CAVEAT`]).
    Anchored {
        /// Txid of the Bloch transaction carrying the DATA0 envelope (opaque).
        txid: [u8; 32],
        /// The anchored DATA0 `sequence` for this namespace.
        sequence: u64,
        /// Confirmation depth at journaling time.
        depth: AnchorDepth,
    },
    /// Deal observed: a provider-reported Filecoin deal for the stored CID.
    /// Provider-reported and unverified by this crate.
    DealObserved(DealInfo),
}

impl Evidence {
    /// The pipeline stage this evidence belongs to.
    pub fn stage(&self) -> Stage {
        match self {
            Evidence::Sealed { .. } => Stage::Sealed,
            Evidence::Uploaded { .. } => Stage::Uploaded,
            Evidence::Anchored { .. } => Stage::Anchored,
            Evidence::DealObserved(_) => Stage::DealObserved,
        }
    }
}

/// One append-only entry: a monotonic index, the caller-supplied observation
/// time, and the evidence itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalRecord {
    /// Position in the log (0-based, gapless, assigned on append).
    pub index: u64,
    /// Unix time the caller recorded this evidence (this crate has no clock).
    pub at_unix: u64,
    /// The evidence payload.
    pub evidence: Evidence,
}

/// Why an [`Journal::append`] was rejected. The log is append-only, so the
/// only failures are ordering violations; nothing is ever mutated on error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JournalError {
    /// The first record must be [`Evidence::Sealed`] — nothing can be
    /// uploaded, anchored, or deal-observed before it is sealed locally.
    MustStartSealed { got: Stage },
    /// The record's stage skips a prerequisite that has no record yet
    /// (e.g. `Anchored` before any `Uploaded`).
    MissingPrerequisite {
        /// The stage the rejected record belongs to.
        got: Stage,
        /// The prerequisite stage that has no record yet.
        needs: Stage,
    },
}

impl core::fmt::Display for JournalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MustStartSealed { got } => {
                write!(f, "journal: first record must be Sealed, got {got:?}")
            }
            Self::MissingPrerequisite { got, needs } => {
                write!(f, "journal: {got:?} requires an earlier {needs:?} record")
            }
        }
    }
}

impl std::error::Error for JournalError {}

/// An append-only evidence log for one backup-set (one DATA0 namespace).
///
/// Records are appended in the fail-safe pipeline order (§7) and never
/// mutated or removed. [`Journal::render`] emits only the four permitted
/// evidence claims (§6) with the verbatim [`ANCHOR_CAVEAT`] — never
/// "secured" / "backed up" / "permanent".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Journal {
    /// The backup-set / DATA0 namespace this log tracks (opaque id).
    pub namespace_id: [u8; 32],
    records: Vec<JournalRecord>,
}

impl Journal {
    /// A fresh, empty log for `namespace_id`.
    pub fn new(namespace_id: [u8; 32]) -> Self {
        Self { namespace_id, records: Vec::new() }
    }

    /// The records so far, in append order (read-only — the log is
    /// append-only).
    pub fn records(&self) -> &[JournalRecord] {
        &self.records
    }

    /// The highest stage reached so far, or `None` for an empty log. Because
    /// stages can only be appended in non-decreasing order, this is exactly
    /// the last record's stage.
    pub fn highest_stage(&self) -> Option<Stage> {
        self.records.last().map(|r| r.evidence.stage())
    }

    /// The most recent [`AnchorDepth`] recorded, if any anchor evidence
    /// exists. Callers use this to render the current anchor status without
    /// walking the whole log.
    pub fn latest_anchor_depth(&self) -> Option<AnchorDepth> {
        self.records.iter().rev().find_map(|r| match &r.evidence {
            Evidence::Anchored { depth, .. } => Some(*depth),
            _ => None,
        })
    }

    /// Append `evidence` observed at `at_unix`, enforcing the fail-safe stage
    /// order: the first record must be [`Evidence::Sealed`], and any later
    /// record's stage must already have every earlier stage present (so an
    /// anchor cannot be recorded before an upload ack, etc.). On success
    /// returns the assigned record index; on an ordering violation returns a
    /// typed [`JournalError`] and leaves the log untouched.
    ///
    /// Re-recording the *same* stage is always allowed (e.g. an anchor
    /// re-observed at a deeper confirmation, or a deal re-observed as its
    /// `end_epoch` advances) — this is how the log resumes and updates
    /// without mutating history.
    pub fn append(&mut self, at_unix: u64, evidence: Evidence) -> Result<u64, JournalError> {
        let stage = evidence.stage();
        match self.highest_stage() {
            None => {
                if stage != Stage::Sealed {
                    return Err(JournalError::MustStartSealed { got: stage });
                }
            }
            Some(highest) => {
                // A record may re-state the current top stage or advance; it
                // may not appear before its prerequisite exists. Since stages
                // only ever grow, "prerequisite present" == "highest >= prereq".
                if let Some(prereq) = stage.prerequisite() {
                    if highest < prereq {
                        return Err(JournalError::MissingPrerequisite { got: stage, needs: prereq });
                    }
                }
            }
        }
        let index = self.records.len() as u64;
        self.records.push(JournalRecord { index, at_unix, evidence });
        Ok(index)
    }

    /// Render the journaled evidence chain as permitted, gated lines (§6).
    ///
    /// Emits **only** the four permitted claims, each with its named evidence,
    /// and stamps the verbatim [`ANCHOR_CAVEAT`] on every anchor line. It never
    /// emits "secured" / "backed up" / "permanent" — [`Journal::render_is_clean`]
    /// asserts this over the output. An empty log renders a single explicit
    /// "no evidence recorded" line (never an optimistic claim).
    pub fn render(&self) -> Vec<String> {
        if self.records.is_empty() {
            return vec!["no evidence recorded".to_string()];
        }
        self.records
            .iter()
            .map(|r| match &r.evidence {
                Evidence::Sealed { manifest_root, entry_count } => {
                    format!(
                        "sealed locally ({entry_count} entries, root {})",
                        hex_prefix(manifest_root)
                    )
                }
                Evidence::Uploaded { cid, size, .. } => {
                    format!(
                        "uploaded (provider ack, CID {}, {size} bytes)",
                        hex_prefix(cid.as_bytes())
                    )
                }
                Evidence::Anchored { txid, sequence, depth } => {
                    let d = match depth {
                        AnchorDepth::Unconfirmed => "unconfirmed".to_string(),
                        AnchorDepth::ConfirmedDepth(n) => format!("confirmed-depth-{n} on a k=4 base"),
                    };
                    format!(
                        "anchored (tx {}, seq {sequence}, {d}) — {ANCHOR_CAVEAT}",
                        hex_prefix(txid)
                    )
                }
                Evidence::DealObserved(deal) => {
                    let id = match deal.deal_id {
                        Some(id) => id.to_string(),
                        None => "pending".to_string(),
                    };
                    let end = match deal.end_epoch {
                        Some(e) => e.to_string(),
                        None => "unreported".to_string(),
                    };
                    format!(
                        "deal observed (dealId {id}, provider {}, endEpoch {end})",
                        deal.provider
                    )
                }
            })
            .collect()
    }

    /// Mechanical vocabulary gate: `true` iff [`Journal::render`]'s output
    /// contains none of [`FORBIDDEN_CLAIMS`] (case-insensitively). The render
    /// is written to satisfy this unconditionally; the check exists so a
    /// future edit that reintroduces a forbidden word is caught by the tests.
    pub fn render_is_clean(&self) -> bool {
        let joined = self.render().join("\n").to_ascii_lowercase();
        !FORBIDDEN_CLAIMS.iter().any(|w| joined.contains(&w.to_ascii_lowercase()))
    }
}

/// Lowercase hex of at most the first 8 bytes of `bytes`, with an ellipsis
/// when truncated. Locator/id shortening for human-readable render lines;
/// NOT a checksum and carries no integrity weight.
fn hex_prefix(bytes: &[u8]) -> String {
    const SHOWN: usize = 8;
    let mut s = String::new();
    for b in bytes.iter().take(SHOWN) {
        s.push_str(&format!("{b:02x}"));
    }
    if bytes.len() > SHOWN {
        s.push('…');
    }
    if s.is_empty() {
        s.push_str("(empty)");
    }
    s
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const NS: [u8; 32] = [0x11; 32];

    fn sealed() -> Evidence {
        Evidence::Sealed { manifest_root: [0xAB; 32], entry_count: 3 }
    }

    fn uploaded() -> Evidence {
        Evidence::Uploaded {
            cid: Cid(b"mock-cid:\x00".to_vec()),
            size: 4096,
            provider_ref: None,
            observed_unix: 1_700_000_100,
        }
    }

    fn anchored(depth: AnchorDepth) -> Evidence {
        Evidence::Anchored { txid: [0xCD; 32], sequence: 0, depth }
    }

    fn deal() -> Evidence {
        Evidence::DealObserved(DealInfo {
            deal_id: Some(42),
            provider: "f01234".to_string(),
            end_epoch: Some(5_000_000),
        })
    }

    // ── append order enforcement ─────────────────────────────────────────

    #[test]
    fn full_pipeline_appends_in_order() {
        let mut j = Journal::new(NS);
        assert_eq!(j.append(1, sealed()), Ok(0));
        assert_eq!(j.append(2, uploaded()), Ok(1));
        assert_eq!(j.append(3, anchored(AnchorDepth::Unconfirmed)), Ok(2));
        assert_eq!(j.append(4, deal()), Ok(3));
        assert_eq!(j.highest_stage(), Some(Stage::DealObserved));
        assert_eq!(j.records().len(), 4);
        // Gapless, ascending indices.
        for (i, r) in j.records().iter().enumerate() {
            assert_eq!(r.index, i as u64);
        }
    }

    #[test]
    fn empty_log_must_start_sealed() {
        let mut j = Journal::new(NS);
        assert_eq!(
            j.append(1, uploaded()),
            Err(JournalError::MustStartSealed { got: Stage::Uploaded })
        );
        assert_eq!(
            j.append(1, anchored(AnchorDepth::Unconfirmed)),
            Err(JournalError::MustStartSealed { got: Stage::Anchored })
        );
        // Rejected appends leave the log untouched.
        assert!(j.records().is_empty());
    }

    #[test]
    fn cannot_skip_a_prerequisite_stage() {
        let mut j = Journal::new(NS);
        j.append(1, sealed()).unwrap();
        // Anchored before any Uploaded: rejected, log unchanged.
        assert_eq!(
            j.append(2, anchored(AnchorDepth::Unconfirmed)),
            Err(JournalError::MissingPrerequisite { got: Stage::Anchored, needs: Stage::Uploaded })
        );
        assert_eq!(j.records().len(), 1);
        // DealObserved before any Anchored: rejected too.
        j.append(2, uploaded()).unwrap();
        assert_eq!(
            j.append(3, deal()),
            Err(JournalError::MissingPrerequisite { got: Stage::DealObserved, needs: Stage::Anchored })
        );
        assert_eq!(j.records().len(), 2);
    }

    #[test]
    fn same_stage_may_be_restated() {
        // An anchor re-observed deeper, and a deal re-observed later, append
        // as NEW records without mutating history (append-only resume).
        let mut j = Journal::new(NS);
        j.append(1, sealed()).unwrap();
        j.append(2, uploaded()).unwrap();
        j.append(3, anchored(AnchorDepth::Unconfirmed)).unwrap();
        j.append(4, anchored(AnchorDepth::ConfirmedDepth(1))).unwrap();
        j.append(5, anchored(AnchorDepth::ConfirmedDepth(6))).unwrap();
        assert_eq!(j.latest_anchor_depth(), Some(AnchorDepth::ConfirmedDepth(6)));
        assert_eq!(j.records().len(), 5);
        // Earlier anchor records are preserved verbatim.
        assert_eq!(
            j.records()[2].evidence,
            anchored(AnchorDepth::Unconfirmed)
        );
    }

    // ── vocabulary gate ──────────────────────────────────────────────────

    #[test]
    fn render_never_emits_forbidden_words() {
        let mut j = Journal::new(NS);
        j.append(1, sealed()).unwrap();
        j.append(2, uploaded()).unwrap();
        j.append(3, anchored(AnchorDepth::ConfirmedDepth(4))).unwrap();
        j.append(4, deal()).unwrap();
        assert!(j.render_is_clean(), "render leaked a forbidden claim");
        let joined = j.render().join("\n").to_ascii_lowercase();
        for w in FORBIDDEN_CLAIMS {
            assert!(!joined.contains(w), "render contained forbidden word {w:?}");
        }
    }

    #[test]
    fn every_anchor_line_carries_the_verbatim_caveat() {
        let mut j = Journal::new(NS);
        j.append(1, sealed()).unwrap();
        j.append(2, uploaded()).unwrap();
        j.append(3, anchored(AnchorDepth::Unconfirmed)).unwrap();
        let lines = j.render();
        let anchor_lines: Vec<_> = lines.iter().filter(|l| l.starts_with("anchored")).collect();
        assert_eq!(anchor_lines.len(), 1);
        assert!(anchor_lines[0].contains(ANCHOR_CAVEAT), "missing verbatim caveat");
    }

    #[test]
    fn render_states_use_permitted_phrasing() {
        let mut j = Journal::new(NS);
        j.append(1, sealed()).unwrap();
        j.append(2, uploaded()).unwrap();
        j.append(3, anchored(AnchorDepth::ConfirmedDepth(2))).unwrap();
        j.append(4, deal()).unwrap();
        let lines = j.render();
        assert!(lines[0].starts_with("sealed locally"));
        assert!(lines[1].starts_with("uploaded (provider ack, CID "));
        assert!(lines[2].starts_with("anchored (tx "));
        assert!(lines[2].contains("confirmed-depth-2 on a k=4 base"));
        assert!(lines[3].starts_with("deal observed (dealId 42"));
    }

    #[test]
    fn unconfirmed_anchor_renders_as_unconfirmed() {
        let mut j = Journal::new(NS);
        j.append(1, sealed()).unwrap();
        j.append(2, uploaded()).unwrap();
        j.append(3, anchored(AnchorDepth::Unconfirmed)).unwrap();
        assert!(j.render()[2].contains("unconfirmed"));
        assert!(!j.render()[2].contains("confirmed-depth"));
    }

    #[test]
    fn empty_log_renders_explicit_no_evidence_and_is_clean() {
        let j = Journal::new(NS);
        assert_eq!(j.render(), vec!["no evidence recorded".to_string()]);
        assert!(j.render_is_clean());
        assert_eq!(j.highest_stage(), None);
        assert_eq!(j.latest_anchor_depth(), None);
    }

    #[test]
    fn deal_with_pending_id_renders_without_a_number() {
        let mut j = Journal::new(NS);
        j.append(1, sealed()).unwrap();
        j.append(2, uploaded()).unwrap();
        j.append(3, anchored(AnchorDepth::ConfirmedDepth(1))).unwrap();
        j.append(
            4,
            Evidence::DealObserved(DealInfo {
                deal_id: None,
                provider: "f0999".to_string(),
                end_epoch: None,
            }),
        )
        .unwrap();
        let line = &j.render()[3];
        assert!(line.contains("dealId pending"));
        assert!(line.contains("endEpoch unreported"));
        assert!(j.render_is_clean());
    }

    #[test]
    fn hex_prefix_shortens_and_marks_truncation() {
        assert_eq!(hex_prefix(&[0x00, 0x01, 0x02]), "000102");
        assert_eq!(hex_prefix(&[0xAB; 32]), "abababababababab…");
        assert_eq!(hex_prefix(&[]), "(empty)");
    }
}
