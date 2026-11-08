// SPDX-License-Identifier: MIT OR Apache-2.0
//! The crossing **audit ledger**: one append-only, SHAKE-256 hash-chained trail
//! (over [`postern_trail`]) that records **every** send, deliver, and **deny** —
//! but **never the bytes that crossed**.
//!
//! Each entry is a [`CrossingRecord`]: the event, the capability, the direction,
//! the paired session, the monotonic counter, the payload **size** and a **SHA-256
//! digest** of the payload, and — for a denial — the honest reason. The digest and
//! size are **attribution, not confidentiality**: they let an operator later
//! reconcile *what was authorized to cross* against *what actually crossed*, and
//! detect if a given blob crossed twice; they reveal nothing about the content and
//! are not a secret. The opaque payload bytes are **never** written to the trail.
//!
//! Durability + tamper-evidence come from `postern-trail`: every append is
//! `fsync`ed before returning, and [`postern_trail::verify_chain`] recomputes every
//! hash and link so any *partial* edit (a flipped byte, a spliced line) is caught.
//! It is **tamper-evident, not tamper-proof** — the machine owner can always
//! rewrite the whole file and recompute every hash; a partial edit cannot hide.
//!
//! Honesty rails: reference-prototype, UNAUDITED. The trail is a local device
//! record; it is never telemetry and never leaves the device.

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use postern_trail::{ChainError, Trail};

use crate::capability::Capability;
use crate::crossing::CrossingRequest;
use crate::error::DenyReason;
use crate::persona::Persona;

/// The three things worth recording about a crossing attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossingEvent {
    /// The near side sealed a crossing and put it on the bearer.
    Sent,
    /// The far side's gate + consent allowed it and the payload was delivered.
    Delivered,
    /// The crossing was refused — by the gate, the signed consent, a stale replay
    /// guard, or the kill-switch. The `reason` field says which.
    Denied,
}

/// One trail entry. Serializes to a flat JSON object (no reserved envelope keys —
/// `v` / `prev_hash` / `hash` belong to the trail crate). **Never** carries payload
/// bytes; only the size and digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossingRecord {
    /// RFC-3339 timestamp the event was recorded (string, so the canonical form has
    /// no numeric ambiguity — the trail hashes over this).
    pub ts: String,
    /// send / deliver / deny.
    pub event: CrossingEvent,
    /// The capability that crossed (or was refused), by its stable machine key.
    pub capability: String,
    /// Origin persona label.
    pub from: String,
    /// Destination persona label.
    pub to: String,
    /// Hex of the 16-byte crossing session id — ties entries to one paired session.
    pub session_id: String,
    /// The crossing's monotonic per-session counter.
    pub counter: u64,
    /// Payload size in bytes — attribution, not the content.
    pub payload_len: usize,
    /// Lowercase-hex **SHA-256** of the payload — attribution, **not**
    /// confidentiality: it identifies *which* blob crossed, it does not hide it and
    /// is not a secret.
    pub payload_sha256: String,
    /// The honest deny reason, present only on a [`CrossingEvent::Denied`] entry.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
}

/// Lowercase-hex SHA-256 of the opaque payload — the attribution digest.
pub fn payload_digest(payload: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(payload);
    hex::encode(h.finalize())
}

fn hex16(sid: &[u8; 16]) -> String {
    hex::encode(sid)
}

/// The append-only crossing audit trail. A thin, honest wrapper over
/// [`postern_trail::Trail`] specialized to [`CrossingRecord`].
pub struct AuditTrail {
    trail: Trail<CrossingRecord>,
}

impl AuditTrail {
    /// Open (creating on first append) the trail at `path`. Resumes an existing
    /// chain from its head.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ChainError> {
        Ok(AuditTrail {
            trail: Trail::open(path)?,
        })
    }

    /// The hash the next appended record links to (persist this out-of-band to
    /// catch tail-truncation with [`postern_trail::verify_chain_to_head`]).
    pub fn head(&self) -> &str {
        self.trail.head()
    }

    /// Record a **sent** crossing (near side). Logs size + digest, never the bytes.
    pub fn record_sent(
        &mut self,
        req: &CrossingRequest,
        to: Persona,
        now_iso: impl Into<String>,
    ) -> Result<(), ChainError> {
        self.append(CrossingEvent::Sent, req, to, now_iso.into(), None)
    }

    /// Record a **delivered** crossing (far side, after gate + consent allowed it).
    pub fn record_delivered(
        &mut self,
        req: &CrossingRequest,
        to: Persona,
        now_iso: impl Into<String>,
    ) -> Result<(), ChainError> {
        self.append(CrossingEvent::Delivered, req, to, now_iso.into(), None)
    }

    /// Record a **denied** crossing with its honest reason (far side).
    pub fn record_denied(
        &mut self,
        req: &CrossingRequest,
        to: Persona,
        now_iso: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<(), ChainError> {
        self.append(
            CrossingEvent::Denied,
            req,
            to,
            now_iso.into(),
            Some(reason.into()),
        )
    }

    fn append(
        &mut self,
        event: CrossingEvent,
        req: &CrossingRequest,
        to: Persona,
        ts: String,
        reason: Option<String>,
    ) -> Result<(), ChainError> {
        let record = CrossingRecord {
            ts,
            event,
            capability: req.capability.key().to_string(),
            from: persona_key(req.from_persona).to_string(),
            to: persona_key(to).to_string(),
            session_id: hex16(&req.session_id),
            counter: req.counter,
            payload_len: req.payload.len(),
            payload_sha256: payload_digest(&req.payload),
            reason,
        };
        self.trail.append(record)?;
        Ok(())
    }
}

fn persona_key(p: Persona) -> &'static str {
    match p {
        Persona::Clean => "clean",
        Persona::GooglePlay => "google-play",
    }
}

// ── In-memory, hash-chained per-endpoint ledger ────────────────────────────────
//
// [`AuditTrail`] above is the durable, `postern-trail`-backed, file-resident audit
// (fsync'd JSONL, SHAKE-256 chained, shared mechanism with yagabona/ezekiel1). The
// types below are a second, complementary in-process ledger held directly by
// [`crate::bridge::CrossingSender`]/[`crate::bridge::CrossingReceiver`] — no file,
// no I/O — so a caller can inspect "what did THIS endpoint decide, this run"
// without opening a trail file. Same honesty rail: it records **size + SHA-256
// digest, never the bytes**, and is attribution, not confidentiality. Its chain is
// its own (SHA-256, not SHAKE-256) and is best-effort integrity for an in-process,
// userland structure — not a substitute for the durable trail above.

/// The size + SHA-256 digest of a crossing payload. **Carries no bytes.**
///
/// This is the only shape in which a payload ever appears in the in-memory ledger:
/// its length and its digest. Recording it is attribution ("a 4 096-byte blob
/// whose digest is … crossed at …"), never confidentiality — the digest reveals
/// nothing to anyone who does not already hold the bytes, and everything to anyone
/// who does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadDigest {
    /// The payload's length in bytes.
    pub len: usize,
    /// SHA-256 over the exact payload bytes.
    pub sha256: [u8; 32],
}

impl PayloadDigest {
    /// Digest a payload. The bytes are read once to hash and are **not** retained.
    pub fn of(bytes: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(bytes);
        let d = h.finalize();
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&d);
        PayloadDigest {
            len: bytes.len(),
            sha256,
        }
    }

    /// Lower-hex of the digest, for logs / the audit UI.
    pub fn hex(&self) -> String {
        hex::encode(self.sha256)
    }

    /// A short head fragment of the digest (first 6 bytes), for compact display.
    pub fn short(&self) -> String {
        hex::encode(&self.sha256[..6])
    }
}

/// How one crossing was decided — the outcome recorded against a
/// [`CrossingDecision`]. Deny-by-default runs through every variant: the ONLY
/// "value crossed" outcome is [`Delivered`](CrossingOutcome::Delivered), reached
/// only when BOTH gates said yes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossingOutcome {
    /// Near side: a live grant was present, so the sealed frame was put on the
    /// bearer. (The far gate still decides delivery independently.)
    Sent,
    /// Far side: the per-crossing guard passed AND the deny-by-default gate said
    /// `Allow` — the payload crossed and was delivered zeroizing.
    Delivered,
    /// Far side: the deny-by-default gate refused this capability into this world.
    Denied(DenyReason),
    /// A protocol/transport-layer refusal on a decoded crossing (replay, stale
    /// counter, wrong session, oversize, …) — fail-closed, nothing crossed. The
    /// `&'static str` is a stable machine kind.
    Rejected(&'static str),
}

impl CrossingOutcome {
    /// A stable, lower-snake machine code for logs / the audit UI and the chain
    /// hash. Never localized, never reordered.
    pub fn code(&self) -> String {
        match self {
            CrossingOutcome::Sent => "sent".to_string(),
            CrossingOutcome::Delivered => "delivered".to_string(),
            CrossingOutcome::Denied(reason) => format!("denied:{}", reason.key()),
            CrossingOutcome::Rejected(kind) => format!("rejected:{kind}"),
        }
    }

    /// True only for the one outcome where value actually crossed.
    pub fn crossed(&self) -> bool {
        matches!(self, CrossingOutcome::Delivered)
    }
}

/// One attributable crossing decision, held in the in-memory [`AuditLedger`].
/// Public metadata + a payload **digest** (size + SHA-256, never the bytes) + the
/// [`CrossingOutcome`]. Named `CrossingDecision` (not `ConsentRecord`) so it never
/// collides with [`crate::consent_record::ConsentRecord`] — the signed, near-side
/// **authorization** to cross, a completely different thing from this record of
/// *how a crossing was decided*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossingDecision {
    /// The 16-byte crossing session this decision belongs to.
    pub session_id: postern_signer_protocol::SessionId,
    /// The crossing's monotonic counter (0 if the decision preceded a counter).
    pub counter: u64,
    /// Which of the five bridges this crossing used.
    pub capability: Capability,
    /// The world the crossing originated from.
    pub from_persona: Persona,
    /// The world the crossing was decided FOR.
    pub to_persona: Persona,
    /// The capability's consequence tier (derived structurally, not requester-set).
    pub tier: postern_signer_protocol::ConsequenceTier,
    /// Size + SHA-256 of the payload. **No bytes.**
    pub digest: PayloadDigest,
    /// How it was decided.
    pub outcome: CrossingOutcome,
    /// When (unix seconds).
    pub at_unix: i64,
}

impl CrossingDecision {
    /// Build a record from a crossing's fields, digesting `payload` in place. The
    /// payload slice is read once to compute the digest and is **not** retained.
    #[allow(clippy::too_many_arguments)]
    fn new(
        session_id: postern_signer_protocol::SessionId,
        counter: u64,
        capability: Capability,
        from_persona: Persona,
        to_persona: Persona,
        payload: &[u8],
        outcome: CrossingOutcome,
        at_unix: i64,
    ) -> Self {
        CrossingDecision {
            session_id,
            counter,
            capability,
            from_persona,
            to_persona,
            tier: capability.tier(),
            digest: PayloadDigest::of(payload),
            outcome,
            at_unix,
        }
    }

    /// Near-side: a live grant was present and the sealed frame went on the bearer.
    #[allow(clippy::too_many_arguments)]
    pub fn sent(
        session_id: postern_signer_protocol::SessionId,
        counter: u64,
        capability: Capability,
        from_persona: Persona,
        to_persona: Persona,
        payload: &[u8],
        at_unix: i64,
    ) -> Self {
        Self::new(session_id, counter, capability, from_persona, to_persona, payload, CrossingOutcome::Sent, at_unix)
    }

    /// Far-side: both gates said yes → delivered.
    #[allow(clippy::too_many_arguments)]
    pub fn delivered(
        session_id: postern_signer_protocol::SessionId,
        counter: u64,
        capability: Capability,
        from_persona: Persona,
        to_persona: Persona,
        payload: &[u8],
        at_unix: i64,
    ) -> Self {
        Self::new(session_id, counter, capability, from_persona, to_persona, payload, CrossingOutcome::Delivered, at_unix)
    }

    /// Far-side: the deny-by-default gate refused this crossing.
    #[allow(clippy::too_many_arguments)]
    pub fn denied(
        session_id: postern_signer_protocol::SessionId,
        counter: u64,
        capability: Capability,
        from_persona: Persona,
        to_persona: Persona,
        payload: &[u8],
        reason: DenyReason,
        at_unix: i64,
    ) -> Self {
        Self::new(session_id, counter, capability, from_persona, to_persona, payload, CrossingOutcome::Denied(reason), at_unix)
    }

    /// A protocol/transport refusal on a decoded crossing (replay/stale/wrong-session/…).
    #[allow(clippy::too_many_arguments)]
    pub fn rejected(
        session_id: postern_signer_protocol::SessionId,
        counter: u64,
        capability: Capability,
        from_persona: Persona,
        to_persona: Persona,
        payload: &[u8],
        kind: &'static str,
        at_unix: i64,
    ) -> Self {
        Self::new(session_id, counter, capability, from_persona, to_persona, payload, CrossingOutcome::Rejected(kind), at_unix)
    }

    /// Did value actually cross (a delivered crossing)?
    pub fn crossed(&self) -> bool {
        self.outcome.crossed()
    }
}

/// One chained entry in the append-only in-memory ledger: a [`CrossingDecision`]
/// anchored by its sequence number and a running hash chain.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// 0-based position in the ledger.
    pub seq: u64,
    /// The attributable crossing decision (metadata + digest + outcome). No bytes.
    pub record: CrossingDecision,
    /// The chain value of the previous entry (all-zero for the first).
    pub prev_chain: [u8; 32],
    /// `SHA-256(domain ‖ prev_chain ‖ seq ‖ canonical(record))`.
    pub chain: [u8; 32],
}

const CHAIN_DOMAIN: &[u8] = b"noporis:bridge-crossing:audit-chain:v1";

/// Fold one record's canonical fields into a chain hash over `prev_chain`.
///
/// Hand-rolled (rather than serde) so the input is byte-for-byte deterministic and
/// independent of any serializer's field ordering. **No payload bytes** enter here
/// — only the digest does.
fn chain_hash(prev_chain: &[u8; 32], seq: u64, record: &CrossingDecision) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CHAIN_DOMAIN);
    h.update(prev_chain);
    h.update(seq.to_le_bytes());
    h.update(record.at_unix.to_le_bytes());
    h.update(record.session_id);
    h.update(record.counter.to_le_bytes());
    h.update(record.capability.key().as_bytes());
    h.update([persona_byte(record.from_persona)]);
    h.update([persona_byte(record.to_persona)]);
    h.update([tier_byte(record.tier)]);
    h.update(record.outcome.code().as_bytes());
    h.update((record.digest.len as u64).to_le_bytes());
    h.update(record.digest.sha256);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

fn persona_byte(p: Persona) -> u8 {
    match p {
        Persona::Clean => 0,
        Persona::GooglePlay => 1,
    }
}

fn tier_byte(t: postern_signer_protocol::ConsequenceTier) -> u8 {
    use postern_signer_protocol::ConsequenceTier::*;
    match t {
        SilentReadOnly => 0,
        SingleTap => 1,
        ExplicitReview => 2,
    }
}

/// An append-only, hash-chained, in-memory ledger of crossing decisions. Held per
/// endpoint (one on the sending persona, one on the receiving persona). **Never
/// stores payload bytes** — only [`PayloadDigest`]s and public metadata.
#[derive(Debug, Clone)]
pub struct AuditLedger {
    entries: Vec<AuditEntry>,
    head: [u8; 32],
}

impl Default for AuditLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLedger {
    /// A fresh, empty ledger (chain head all-zero).
    pub fn new() -> Self {
        AuditLedger {
            entries: Vec::new(),
            head: [0u8; 32],
        }
    }

    /// Append one decision. Append-only: there is no update or delete. Returns the
    /// stored entry (its `seq` and `chain`).
    pub fn append(&mut self, record: CrossingDecision) -> &AuditEntry {
        let seq = self.entries.len() as u64;
        let prev_chain = self.head;
        let chain = chain_hash(&prev_chain, seq, &record);
        self.head = chain;
        self.entries.push(AuditEntry {
            seq,
            record,
            prev_chain,
            chain,
        });
        // Safe: we just pushed.
        self.entries.last().expect("just appended")
    }

    /// The entries, oldest first.
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// The current chain head (all-zero when empty).
    pub fn head(&self) -> [u8; 32] {
        self.head
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The most recent entry, if any.
    pub fn last(&self) -> Option<&AuditEntry> {
        self.entries.last()
    }

    /// Recompute the chain from scratch and confirm every link — detects any
    /// altered, dropped, or reordered entry. Best-effort integrity for an
    /// in-process ledger (a host that owns this process can forge the whole chain).
    pub fn verify(&self) -> bool {
        let mut prev = [0u8; 32];
        for (i, e) in self.entries.iter().enumerate() {
            if e.seq != i as u64 {
                return false;
            }
            if e.prev_chain != prev {
                return false;
            }
            let expect = chain_hash(&prev, e.seq, &e.record);
            if e.chain != expect {
                return false;
            }
            prev = e.chain;
        }
        prev == self.head
    }
}

#[cfg(test)]
mod in_memory_ledger_tests {
    use super::*;

    fn rec(counter: u64, payload: &[u8]) -> CrossingDecision {
        CrossingDecision::delivered(
            [7u8; 16],
            counter,
            Capability::Clipboard,
            Persona::GooglePlay,
            Persona::Clean,
            payload,
            1_752_000_000,
        )
    }

    #[test]
    fn digest_records_size_and_hash_but_no_bytes() {
        let d = PayloadDigest::of(b"hello world");
        assert_eq!(d.len, 11);
        assert_eq!(d.hex(), "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
        assert_eq!(std::mem::size_of::<PayloadDigest>(), std::mem::size_of::<usize>() + 32);
    }

    #[test]
    fn ledger_is_append_only_and_chained() {
        let mut l = AuditLedger::new();
        assert!(l.is_empty());
        l.append(rec(1, b"a"));
        l.append(rec(2, b"bb"));
        l.append(rec(3, b"ccc"));
        assert_eq!(l.len(), 3);
        assert!(l.verify());
        assert_eq!(l.entries()[0].prev_chain, [0u8; 32]);
        assert_eq!(l.entries()[1].prev_chain, l.entries()[0].chain);
        assert_eq!(l.entries()[2].prev_chain, l.entries()[1].chain);
        assert_eq!(l.head(), l.entries()[2].chain);
    }

    #[test]
    fn tampering_with_an_entry_breaks_verify() {
        let mut l = AuditLedger::new();
        l.append(rec(1, b"a"));
        l.append(rec(2, b"bb"));
        assert!(l.verify());
        l.entries[0].record = rec(1, b"TAMPERED");
        assert!(!l.verify(), "altering a recorded digest must break the chain");
    }

    #[test]
    fn tampering_with_a_middle_entry_breaks_verify() {
        // Mutate a MIDDLE entry of a 3-entry chain (not just the head): every link
        // downstream must fail to recompute, so a spliced-in-the-middle edit cannot
        // hide behind a still-valid head.
        let mut l = AuditLedger::new();
        l.append(rec(1, b"a"));
        l.append(rec(2, b"bb"));
        l.append(rec(3, b"ccc"));
        assert!(l.verify());
        l.entries[1].record = rec(2, b"TAMPERED-MIDDLE");
        assert!(!l.verify(), "a mutated middle entry must break verify()");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Capability;
    use postern_trail::verify_chain;

    fn req(counter: u64, payload: &[u8]) -> CrossingRequest {
        CrossingRequest {
            session_id: [0xAB; 16],
            req_nonce: [1u8; 32],
            counter,
            capability: Capability::Clipboard,
            from_persona: Persona::GooglePlay,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn records_events_but_never_the_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("crossings.jsonl");
        let mut audit = AuditTrail::open(&path).unwrap();

        let secret = b"top-secret-clipboard-blob";
        audit
            .record_sent(&req(1, secret), Persona::Clean, "2026-07-13T00:00:00Z")
            .unwrap();
        audit
            .record_delivered(&req(1, secret), Persona::Clean, "2026-07-13T00:00:01Z")
            .unwrap();

        // Two entries, chain verifies.
        assert_eq!(verify_chain(&path).unwrap(), 2);

        // The raw bytes are NOWHERE in the trail; the digest IS.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("top-secret"), "payload bytes must never be logged");
        assert!(raw.contains(&payload_digest(secret)), "digest is recorded");
        assert!(raw.contains("\"payload_len\":25"));
    }

    #[test]
    fn denied_entries_carry_the_reason() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("crossings.jsonl");
        let mut audit = AuditTrail::open(&path).unwrap();
        let secret = b"denied-secret-payload-bytes";
        audit
            .record_denied(&req(2, secret), Persona::Clean, "2026-07-13T00:00:02Z", "kill-switch engaged")
            .unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"event\":\"denied\""));
        assert!(raw.contains("kill-switch engaged"));
        // Privacy rail on the DENY path too: a refused crossing is audited by digest,
        // never by bytes — the payload of a denied attempt must not leak into the trail.
        assert!(!raw.contains("denied-secret"), "denied payload bytes must never be logged");
        assert!(raw.contains(&payload_digest(secret)), "denied entry records the digest");
    }

    #[test]
    fn a_single_byte_tamper_of_a_line_is_caught() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("crossings.jsonl");
        let mut audit = AuditTrail::open(&path).unwrap();
        for i in 0..3 {
            audit
                .record_sent(&req(i, b"blob"), Persona::Clean, "2026-07-13T00:00:00Z")
                .unwrap();
        }
        // Flip one character in the middle line's counter; leave its hash.
        let original = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = original.lines().map(str::to_string).collect();
        lines[1] = lines[1].replacen("\"counter\":1", "\"counter\":9", 1);
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        assert!(verify_chain(&path).is_err(), "partial edit must be detected");
    }
}
