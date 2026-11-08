// SPDX-License-Identifier: MIT OR Apache-2.0
//! The signed, time-boxed, per-item, per-direction **`ConsentRecord`** — the
//! cryptographic proof that the near side authorized *this* capability to cross in
//! *this* direction, right now.
//!
//! ## Who may mint
//!
//! **Only the near (Clean / PQ-aware) side mints.** A [`ConsentAuthority`] holds a
//! signing key; it is the sole thing that can produce a [`ConsentRecord`]. The
//! Google-Play side can build a [`ConsentRequest`] (an *ask* — it carries no
//! signature and there is no API on it to add one) but **can never mint**. On
//! delivery the near side checks a request against the signed records it has
//! itself minted. A compromised far side can request all day; it cannot forge a yes.
//!
//! ## What is pinned
//!
//! The signature covers a domain-separated preimage binding **all** of: the record
//! id, the paired [`SessionId`], the [`Capability`], the **[`Direction`]**
//! (`from → to`, cryptographically pinned — a record minted for `GooglePlay → Clean`
//! cannot be replayed as `Clean → GooglePlay`), the [`ConsentScope`]
//! (`single | session`), the issue/expiry instants, and the peer device. Change any
//! one byte and the signature fails.
//!
//! ## The 5-step fail-closed check (before every crossing)
//!
//! [`ConsentRecord::check`] runs, in order, refusing at the first failure:
//! 1. **signature** valid under the pinned near-side key (mint authority);
//! 2. **session** binding matches this endpoint's paired session;
//! 3. **direction** pinned matches the crossing's actual `from → to`;
//! 4. **capability** matches the crossing's capability;
//! 5. **time-box** live — `issued_at ≤ now < expires_at` (not expired, not future).
//!
//! ## Four revocation paths ([`ConsentLedger`])
//!
//! A minted yes can be taken back four ways: (1) explicit per-record revoke by id;
//! (2) close a capability lane (revoke every record for that capability); (3) the
//! kill-switch (drop the span — deny everything); (4) time-box **expiry** (passive,
//! caught by step 5). A `single`-scope record additionally *self-retires* after one
//! use (scope semantics, not a fifth revocation).
//!
//! ## Honesty rails
//!
//! Reference-prototype, UNAUDITED. The reference [`ConsentAuthority`] signs with a
//! **classical Ed25519** key standing in for the near side's real on-device
//! PQ-hybrid signer; the near side is where PQ lives on a real device. A signature
//! is **attribution, not confidentiality** — it says *who authorized*, it hides
//! nothing. A rooted host that owns the signing key defeats this, like every other
//! boundary here.

use std::collections::HashSet;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use postern_signer_protocol::SessionId;

use crate::capability::Capability;
use crate::persona::Persona;

/// Domain separator for the consent-record signature preimage. Distinct from every
/// other signing/derivation domain so a signature can never be cross-used.
const CONSENT_SIG_DOMAIN: &[u8] = b"noporis:consent-record:sig:v1";

/// The cryptographically-pinned direction of a crossing: from one persona to
/// another. A record minted for one direction never authorizes the reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Direction {
    pub from: Persona,
    pub to: Persona,
}

impl Direction {
    pub fn new(from: Persona, to: Persona) -> Self {
        Direction { from, to }
    }
}

/// How long a minted yes lasts. Both are time-boxed by `expires_at`; the scope
/// governs *how many crossings* the yes covers within that window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentScope {
    /// A one-shot yes: authorizes exactly **one** crossing, then self-retires
    /// (see [`ConsentLedger::commit_use`]).
    Single,
    /// A yes for the session: authorizes **many** crossings until it expires or is
    /// revoked.
    Session,
}

/// A refusal from the consent layer. Fail-closed: anything not an explicit, live,
/// correctly-signed, correctly-directed yes lands here.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConsentError {
    /// Step 1: the signature did not verify under the pinned near-side key. Either
    /// it was not minted by the near side, or a pinned field was altered.
    #[error("consent signature invalid: not minted by the near side, or a pinned field was altered")]
    BadSignature,
    /// Step 2: the record is bound to a different paired session.
    #[error("consent bound to a different paired session")]
    WrongSession,
    /// Step 3: the record's pinned direction does not match the crossing's `from → to`.
    #[error("consent direction mismatch: minted for a different from→to")]
    WrongDirection,
    /// Step 4: the record authorizes a different capability.
    #[error("consent capability mismatch: minted for a different capability")]
    WrongCapability,
    /// Step 5: the time-box has lapsed (`now ≥ expires_at`) — revocation path #4.
    #[error("consent expired: the time-box has lapsed")]
    Expired,
    /// Step 5: the record is not yet valid (`now < issued_at`) — a future-dated yes.
    #[error("consent not yet valid: issued in the future")]
    NotYetValid,
    /// Revocation path #1: this record was explicitly revoked by id.
    #[error("consent revoked: this authorization was explicitly withdrawn")]
    Revoked,
    /// Revocation path #2: this capability's lane was closed (all its records gone).
    #[error("consent capability lane closed: this capability was revoked wholesale")]
    CapabilityClosed,
    /// Revocation path #3: the kill-switch is engaged — the span is cut.
    #[error("consent denied: kill-switch engaged, the span is cut")]
    KillSwitchEngaged,
    /// A `single`-scope record already spent its one crossing.
    #[error("consent already used: this single-use authorization is spent")]
    AlreadyUsed,
    /// No admitted record matches this crossing (no yes was ever minted for it).
    #[error("no consent: no live authorization exists for this crossing")]
    NoRecord,
}

fn persona_code(p: Persona) -> u8 {
    match p {
        Persona::Clean => 0,
        Persona::GooglePlay => 1,
    }
}

fn capability_code(c: Capability) -> u8 {
    // Stable index into the exhaustive, ordered set.
    Capability::ALL
        .iter()
        .position(|&x| x == c)
        .expect("Capability is in ALL") as u8
}

fn scope_code(s: ConsentScope) -> u8 {
    match s {
        ConsentScope::Single => 0,
        ConsentScope::Session => 1,
    }
}

/// The signed authorization. Immutable once minted — all mutable lifecycle
/// (revocation, single-use consumption) lives in the [`ConsentLedger`], never in
/// the record, so the signed bytes never change under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentRecord {
    /// Unique per-record id (also the handle for explicit revocation).
    pub id: [u8; 16],
    /// The 16-byte crossing session id this yes is bound to.
    pub session_id: SessionId,
    /// The one capability this yes authorizes.
    pub capability: Capability,
    /// The cryptographically-pinned crossing direction.
    pub direction: Direction,
    /// One-shot vs session.
    pub scope: ConsentScope,
    /// Not valid before this instant (unix seconds).
    pub issued_at_unix: i64,
    /// Not valid at or after this instant (unix seconds) — the time-box.
    pub expires_at_unix: i64,
    /// The peer device this yes serves.
    pub peer_device: String,
    /// The near-side verifying (public) key that minted this record — 32 raw bytes.
    pub signer_pub: [u8; 32],
    /// Ed25519 signature over the domain-separated preimage — 64 raw bytes.
    pub signature: [u8; 64],
}

/// Borrowed view over exactly the fields the signature preimage commits to —
/// mirrors [`ConsentRecord`]'s signed fields 1:1. Exists solely to keep
/// [`ConsentRecord::preimage`] to one argument instead of one-per-field.
struct PreimageFields<'a> {
    id: &'a [u8; 16],
    session_id: &'a SessionId,
    capability: Capability,
    direction: Direction,
    scope: ConsentScope,
    issued_at_unix: i64,
    expires_at_unix: i64,
    peer_device: &'a str,
}

impl ConsentRecord {
    /// The exact bytes the signature commits to. Length-prefixed where variable so
    /// no two distinct records share a preimage.
    fn preimage(fields: PreimageFields<'_>) -> Vec<u8> {
        let mut m = Vec::with_capacity(CONSENT_SIG_DOMAIN.len() + 64 + fields.peer_device.len());
        m.extend_from_slice(CONSENT_SIG_DOMAIN);
        m.extend_from_slice(fields.id);
        m.extend_from_slice(fields.session_id);
        m.push(capability_code(fields.capability));
        m.push(persona_code(fields.direction.from));
        m.push(persona_code(fields.direction.to));
        m.push(scope_code(fields.scope));
        m.extend_from_slice(&fields.issued_at_unix.to_be_bytes());
        m.extend_from_slice(&fields.expires_at_unix.to_be_bytes());
        m.extend_from_slice(&(fields.peer_device.len() as u32).to_be_bytes());
        m.extend_from_slice(fields.peer_device.as_bytes());
        m
    }

    /// Recompute this record's signing preimage (for verification).
    fn own_preimage(&self) -> Vec<u8> {
        Self::preimage(PreimageFields {
            id: &self.id,
            session_id: &self.session_id,
            capability: self.capability,
            direction: self.direction,
            scope: self.scope,
            issued_at_unix: self.issued_at_unix,
            expires_at_unix: self.expires_at_unix,
            peer_device: &self.peer_device,
        })
    }

    /// **The 5-step fail-closed check, run before every crossing.** Verifies this
    /// record authorizes a crossing of `capability` in direction `from → to` on
    /// session `session_id` at `now_unix`, minted by `near_pub`.
    ///
    /// Order (refuse at first failure): signature → session → direction →
    /// capability → time-box. Pure: it mutates nothing (single-use consumption and
    /// revocation are the ledger's job).
    pub fn check(
        &self,
        near_pub: &[u8; 32],
        session_id: &SessionId,
        capability: Capability,
        from: Persona,
        to: Persona,
        now_unix: i64,
    ) -> Result<(), ConsentError> {
        // 1. Signature under the pinned near-side minting key.
        let vk = VerifyingKey::from_bytes(near_pub).map_err(|_| ConsentError::BadSignature)?;
        // The record must also claim the key we are pinning to (no key substitution).
        if self.signer_pub != *near_pub {
            return Err(ConsentError::BadSignature);
        }
        let sig = Signature::from_bytes(&self.signature);
        vk.verify(&self.own_preimage(), &sig)
            .map_err(|_| ConsentError::BadSignature)?;

        // 2. Session binding.
        if &self.session_id != session_id {
            return Err(ConsentError::WrongSession);
        }

        // 3. Direction pinned.
        if self.direction.from != from || self.direction.to != to {
            return Err(ConsentError::WrongDirection);
        }

        // 4. Capability.
        if self.capability != capability {
            return Err(ConsentError::WrongCapability);
        }

        // 5. Time-box (revocation path #4 = expiry).
        if now_unix < self.issued_at_unix {
            return Err(ConsentError::NotYetValid);
        }
        if now_unix >= self.expires_at_unix {
            return Err(ConsentError::Expired);
        }

        Ok(())
    }
}

/// The near side's **minting authority** — the sole holder of the signing key.
/// There is no way to obtain a [`ConsentRecord`] except through one of these.
pub struct ConsentAuthority {
    signing: SigningKey,
    next_id: u128,
}

impl ConsentAuthority {
    /// Mint a fresh authority with an OS-entropy signing key.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("OS entropy for the near-side signing key");
        Self::from_seed(seed)
    }

    /// A deterministic authority from a 32-byte seed (tests/demos, or a device that
    /// derives its near-side key from sealed material).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        ConsentAuthority {
            signing: SigningKey::from_bytes(&seed),
            next_id: 1,
        }
    }

    /// The near-side verifying (public) key — pin this on the checking side.
    pub fn verifying_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Mint a signed [`ConsentRecord`]. This is the near-side-only operation.
    #[allow(clippy::too_many_arguments)]
    pub fn mint(
        &mut self,
        session_id: SessionId,
        capability: Capability,
        direction: Direction,
        scope: ConsentScope,
        issued_at_unix: i64,
        expires_at_unix: i64,
        peer_device: impl Into<String>,
    ) -> ConsentRecord {
        let peer_device = peer_device.into();
        let mut id = [0u8; 16];
        id.copy_from_slice(&self.next_id.to_be_bytes());
        self.next_id += 1;

        let preimage = ConsentRecord::preimage(PreimageFields {
            id: &id,
            session_id: &session_id,
            capability,
            direction,
            scope,
            issued_at_unix,
            expires_at_unix,
            peer_device: &peer_device,
        });
        let sig: Signature = self.signing.sign(&preimage);

        ConsentRecord {
            id,
            session_id,
            capability,
            direction,
            scope,
            issued_at_unix,
            expires_at_unix,
            peer_device,
            signer_pub: self.verifying_key(),
            signature: sig.to_bytes(),
        }
    }
}

/// A **request** from the Google-Play side: an *ask*, never a yes. It carries no
/// signature and there is no method to add one — proof, by type, that the
/// less-private side can request a crossing but can never mint the authorization
/// for it. The near side answers a request by checking its minted records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentRequest {
    pub session_id: SessionId,
    pub capability: Capability,
    pub direction: Direction,
    pub peer_device: String,
}

/// The checking-side ledger of minted authorizations, plus the four revocation
/// paths. Holds the pinned near-side key and runs [`ConsentRecord::check`] on
/// admission and again on every authorize (defense in depth).
pub struct ConsentLedger {
    near_pub: [u8; 32],
    records: Vec<ConsentRecord>,
    /// Revocation path #1: explicit per-record revoke by id.
    revoked_ids: HashSet<[u8; 16]>,
    /// Revocation path #2: closed capability lanes.
    revoked_caps: HashSet<Capability>,
    /// Revocation path #3: the kill-switch (drop the span).
    kill_switch: bool,
    /// `single`-scope records that already spent their one crossing.
    consumed_ids: HashSet<[u8; 16]>,
}

/// A granted authorization handle returned by [`ConsentLedger::authorize`]: the
/// record id and its scope, so the caller can [`commit_use`](ConsentLedger::commit_use)
/// a `single` record after the crossing actually completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authorized {
    pub id: [u8; 16],
    pub scope: ConsentScope,
}

impl ConsentLedger {
    /// A fresh ledger pinning `near_pub` as the only key whose records it will trust.
    pub fn new(near_pub: [u8; 32]) -> Self {
        ConsentLedger {
            near_pub,
            records: Vec::new(),
            revoked_ids: HashSet::new(),
            revoked_caps: HashSet::new(),
            kill_switch: false,
            consumed_ids: HashSet::new(),
        }
    }

    /// Admit a minted record. Rejects it up front unless its **signature** verifies
    /// under the pinned near-side key — a record from any other key never enters
    /// the ledger. (Session/direction/time are re-checked per crossing in
    /// [`authorize`](Self::authorize).)
    pub fn admit(&mut self, record: ConsentRecord) -> Result<(), ConsentError> {
        if record.signer_pub != self.near_pub {
            return Err(ConsentError::BadSignature);
        }
        let vk = VerifyingKey::from_bytes(&self.near_pub).map_err(|_| ConsentError::BadSignature)?;
        let sig = Signature::from_bytes(&record.signature);
        vk.verify(&record.own_preimage(), &sig)
            .map_err(|_| ConsentError::BadSignature)?;
        self.records.push(record);
        Ok(())
    }

    /// Revocation path #1: explicitly withdraw one record by id.
    pub fn revoke(&mut self, id: [u8; 16]) {
        self.revoked_ids.insert(id);
    }

    /// Revocation path #2: close a capability lane — revoke every record for it.
    pub fn revoke_capability(&mut self, capability: Capability) {
        self.revoked_caps.insert(capability);
    }

    /// Revocation path #1, wholesale: explicitly withdraw EVERY admitted record
    /// not already revoked. **Monotonic — there is no un-revoke.** Unlike the
    /// kill-switch flag (path #3, which is reversible and only cuts the lane),
    /// records revoked here never come back: disengaging the kill-switch later
    /// reopens the LANE, but each consent must be freshly re-minted and
    /// re-admitted.
    ///
    /// This is the exact public surface the `noporis-signer-glue` crate's
    /// `ConsentRevoker` port asks of this ledger ("all this crate needs from
    /// Dev B is a public `revoke_all(reason) -> count`"), and what
    /// [`crate::daemon::Daemon::shutdown`] calls. Returns how many records were
    /// NEWLY revoked; idempotent — a second call once everything is revoked
    /// returns `0`. `reason` exists for signature parity with that port and for
    /// the caller's audit trail — the ledger itself stores no prose.
    pub fn revoke_all(&mut self, _reason: &str) -> usize {
        let mut newly = 0;
        for rec in &self.records {
            if self.revoked_ids.insert(rec.id) {
                newly += 1;
            }
        }
        newly
    }

    /// Revocation path #3: engage the kill-switch — deny every crossing until
    /// disengaged. Never touches sealed wallet state (the ledger holds none).
    pub fn engage_kill_switch(&mut self) {
        self.kill_switch = true;
    }

    /// Disengage the kill-switch (explicit; never lapses on a timer).
    pub fn disengage_kill_switch(&mut self) {
        self.kill_switch = false;
    }

    pub fn kill_switch_engaged(&self) -> bool {
        self.kill_switch
    }

    /// Spend a `single`-scope record after its crossing completed. Idempotent for
    /// `session` records (they are never consumed). Call **only** after the
    /// crossing was actually delivered.
    pub fn commit_use(&mut self, granted: Authorized) {
        if granted.scope == ConsentScope::Single {
            self.consumed_ids.insert(granted.id);
        }
    }

    /// Authorize one crossing: run all four revocation checks, then the signed
    /// 5-step [`ConsentRecord::check`] against each admitted record, returning the
    /// first fully-valid one. Fail-closed at the first obstacle.
    ///
    /// Precedence: kill-switch (path #3) denies everything first; then, per
    /// candidate, explicit-revoke (#1) and capability-close (#2) and single-use
    /// consumption skip a record before its 5-step check (which itself catches
    /// expiry, #4). If no record survives, the most-specific error seen is
    /// returned, or [`ConsentError::NoRecord`] if none matched at all.
    pub fn authorize(
        &self,
        session_id: &SessionId,
        capability: Capability,
        from: Persona,
        to: Persona,
        now_unix: i64,
    ) -> Result<Authorized, ConsentError> {
        // Path #3: the kill-switch cuts the span wholesale.
        if self.kill_switch {
            return Err(ConsentError::KillSwitchEngaged);
        }
        // Path #2: a closed capability lane denies before any per-record work.
        if self.revoked_caps.contains(&capability) {
            return Err(ConsentError::CapabilityClosed);
        }

        let mut last_err = ConsentError::NoRecord;
        for rec in &self.records {
            // Path #1: explicitly revoked record.
            if self.revoked_ids.contains(&rec.id) {
                last_err = ConsentError::Revoked;
                continue;
            }
            // single-use already spent.
            if self.consumed_ids.contains(&rec.id) {
                last_err = ConsentError::AlreadyUsed;
                continue;
            }
            match rec.check(&self.near_pub, session_id, capability, from, to, now_unix) {
                Ok(()) => {
                    return Ok(Authorized {
                        id: rec.id,
                        scope: rec.scope,
                    })
                }
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_752_000_000;
    const SID: SessionId = [0x11; 16];

    fn authority() -> ConsentAuthority {
        ConsentAuthority::from_seed([7u8; 32])
    }

    fn g2c() -> Direction {
        Direction::new(Persona::GooglePlay, Persona::Clean)
    }

    #[test]
    fn a_minted_record_passes_the_five_step_check() {
        let mut a = authority();
        let rec = a.mint(SID, Capability::Clipboard, g2c(), ConsentScope::Session, NOW, NOW + 600, "peer");
        assert!(rec
            .check(&a.verifying_key(), &SID, Capability::Clipboard, Persona::GooglePlay, Persona::Clean, NOW)
            .is_ok());
    }

    #[test]
    fn a_flipped_signature_byte_fails_step_1() {
        let mut a = authority();
        let mut rec = a.mint(SID, Capability::Files, g2c(), ConsentScope::Session, NOW, NOW + 600, "peer");
        rec.signature[0] ^= 0x01;
        assert_eq!(
            rec.check(&a.verifying_key(), &SID, Capability::Files, Persona::GooglePlay, Persona::Clean, NOW),
            Err(ConsentError::BadSignature)
        );
    }

    #[test]
    fn direction_is_cryptographically_pinned() {
        let mut a = authority();
        // Minted for GooglePlay → Clean; checked as the reverse must fail on direction.
        let rec = a.mint(SID, Capability::Clipboard, g2c(), ConsentScope::Session, NOW, NOW + 600, "peer");
        assert_eq!(
            rec.check(&a.verifying_key(), &SID, Capability::Clipboard, Persona::Clean, Persona::GooglePlay, NOW),
            Err(ConsentError::WrongDirection)
        );
    }

    #[test]
    fn wrong_capability_and_session_are_caught() {
        let mut a = authority();
        let rec = a.mint(SID, Capability::Clipboard, g2c(), ConsentScope::Session, NOW, NOW + 600, "peer");
        assert_eq!(
            rec.check(&a.verifying_key(), &SID, Capability::Mic, Persona::GooglePlay, Persona::Clean, NOW),
            Err(ConsentError::WrongCapability)
        );
        let other: SessionId = [0x22; 16];
        assert_eq!(
            rec.check(&a.verifying_key(), &other, Capability::Clipboard, Persona::GooglePlay, Persona::Clean, NOW),
            Err(ConsentError::WrongSession)
        );
    }

    #[test]
    fn time_box_expiry_is_revocation_path_four() {
        let mut a = authority();
        let rec = a.mint(SID, Capability::Files, g2c(), ConsentScope::Session, NOW, NOW + 10, "peer");
        assert_eq!(
            rec.check(&a.verifying_key(), &SID, Capability::Files, Persona::GooglePlay, Persona::Clean, NOW + 10),
            Err(ConsentError::Expired)
        );
        assert_eq!(
            rec.check(&a.verifying_key(), &SID, Capability::Files, Persona::GooglePlay, Persona::Clean, NOW - 1),
            Err(ConsentError::NotYetValid)
        );
    }

    #[test]
    fn step_1_rejects_key_substitution() {
        // A record correctly signed by one key, checked while pinning a DIFFERENT
        // near key, must fail step 1 — the record's claimed `signer_pub` is compared
        // to the pinned key before the signature is even verified, so no attacker can
        // swap in their own key + valid-under-that-key signature.
        let mut real = authority();
        let attacker = ConsentAuthority::from_seed([0xAB; 32]);
        let rec = real.mint(SID, Capability::Clipboard, g2c(), ConsentScope::Session, NOW, NOW + 600, "peer");
        assert_eq!(
            rec.check(&attacker.verifying_key(), &SID, Capability::Clipboard, Persona::GooglePlay, Persona::Clean, NOW),
            Err(ConsentError::BadSignature),
            "a record must not verify under a key it does not claim"
        );
    }

    #[test]
    fn authorize_with_no_admitted_record_denies_no_record() {
        // Fail-closed default: an empty ledger authorizes nothing.
        let a = authority();
        let l = ConsentLedger::new(a.verifying_key());
        assert_eq!(
            l.authorize(&SID, Capability::Clipboard, Persona::GooglePlay, Persona::Clean, NOW),
            Err(ConsentError::NoRecord)
        );
    }

    #[test]
    fn authorize_surfaces_the_direction_mismatch_as_the_last_error() {
        // A record exists but for the reverse direction: authorize must fail closed,
        // surfacing the most-specific per-record error (WrongDirection), never a yes.
        let mut a = authority();
        let mut l = ConsentLedger::new(a.verifying_key());
        let rec = a.mint(SID, Capability::Clipboard, g2c(), ConsentScope::Session, NOW, NOW + 600, "peer");
        l.admit(rec).unwrap();
        assert_eq!(
            l.authorize(&SID, Capability::Clipboard, Persona::Clean, Persona::GooglePlay, NOW),
            Err(ConsentError::WrongDirection)
        );
    }

    #[test]
    fn a_foreign_key_cannot_mint_into_the_ledger() {
        let mut near = authority();
        let mut attacker = ConsentAuthority::from_seed([9u8; 32]);
        let forged = attacker.mint(SID, Capability::Clipboard, g2c(), ConsentScope::Session, NOW, NOW + 600, "peer");
        let mut ledger = ConsentLedger::new(near.verifying_key());
        // The attacker's record does not verify under the pinned near key.
        assert_eq!(ledger.admit(forged), Err(ConsentError::BadSignature));
        // The genuine near record admits fine.
        let ok = near.mint(SID, Capability::Clipboard, g2c(), ConsentScope::Session, NOW, NOW + 600, "peer");
        assert!(ledger.admit(ok).is_ok());
    }

    #[test]
    fn single_use_self_retires_after_one_crossing() {
        let mut a = authority();
        let mut ledger = ConsentLedger::new(a.verifying_key());
        let rec = a.mint(SID, Capability::Clipboard, g2c(), ConsentScope::Single, NOW, NOW + 600, "peer");
        ledger.admit(rec).unwrap();

        let granted = ledger
            .authorize(&SID, Capability::Clipboard, Persona::GooglePlay, Persona::Clean, NOW)
            .expect("first use ok");
        assert_eq!(granted.scope, ConsentScope::Single);
        ledger.commit_use(granted);
        // The second attempt is denied: the single-use yes is spent.
        assert_eq!(
            ledger.authorize(&SID, Capability::Clipboard, Persona::GooglePlay, Persona::Clean, NOW),
            Err(ConsentError::AlreadyUsed)
        );
    }

    #[test]
    fn session_scope_authorizes_repeatedly() {
        let mut a = authority();
        let mut ledger = ConsentLedger::new(a.verifying_key());
        let rec = a.mint(SID, Capability::Clipboard, g2c(), ConsentScope::Session, NOW, NOW + 600, "peer");
        ledger.admit(rec).unwrap();
        let g = ledger
            .authorize(&SID, Capability::Clipboard, Persona::GooglePlay, Persona::Clean, NOW)
            .unwrap();
        ledger.commit_use(g); // no-op for session scope
        assert!(ledger
            .authorize(&SID, Capability::Clipboard, Persona::GooglePlay, Persona::Clean, NOW)
            .is_ok());
    }

    #[test]
    fn four_revocation_paths_each_deny() {
        let mut a = authority();
        let vk = a.verifying_key();

        // Path #1: explicit revoke by id.
        {
            let mut l = ConsentLedger::new(vk);
            let rec = a.mint(SID, Capability::Clipboard, g2c(), ConsentScope::Session, NOW, NOW + 600, "peer");
            let id = rec.id;
            l.admit(rec).unwrap();
            l.revoke(id);
            assert_eq!(
                l.authorize(&SID, Capability::Clipboard, Persona::GooglePlay, Persona::Clean, NOW),
                Err(ConsentError::Revoked)
            );
        }
        // Path #2: capability lane closed.
        {
            let mut l = ConsentLedger::new(vk);
            let rec = a.mint(SID, Capability::Files, g2c(), ConsentScope::Session, NOW, NOW + 600, "peer");
            l.admit(rec).unwrap();
            l.revoke_capability(Capability::Files);
            assert_eq!(
                l.authorize(&SID, Capability::Files, Persona::GooglePlay, Persona::Clean, NOW),
                Err(ConsentError::CapabilityClosed)
            );
        }
        // Path #3: kill-switch.
        {
            let mut l = ConsentLedger::new(vk);
            let rec = a.mint(SID, Capability::Mic, g2c(), ConsentScope::Session, NOW, NOW + 600, "peer");
            l.admit(rec).unwrap();
            l.engage_kill_switch();
            assert_eq!(
                l.authorize(&SID, Capability::Mic, Persona::GooglePlay, Persona::Clean, NOW),
                Err(ConsentError::KillSwitchEngaged)
            );
        }
        // Path #4: expiry.
        {
            let mut l = ConsentLedger::new(vk);
            let rec = a.mint(SID, Capability::Camera, g2c(), ConsentScope::Session, NOW, NOW + 5, "peer");
            l.admit(rec).unwrap();
            assert_eq!(
                l.authorize(&SID, Capability::Camera, Persona::GooglePlay, Persona::Clean, NOW + 5),
                Err(ConsentError::Expired)
            );
        }
    }

    #[test]
    fn revoke_all_cuts_every_live_record_and_is_idempotent() {
        let mut a = authority();
        let vk = a.verifying_key();
        let mut l = ConsentLedger::new(vk);
        let rec1 = a.mint(SID, Capability::Clipboard, g2c(), ConsentScope::Session, NOW, NOW + 600, "peer");
        let rec2 = a.mint(SID, Capability::Files, g2c(), ConsentScope::Session, NOW, NOW + 600, "peer");
        l.admit(rec1).unwrap();
        l.admit(rec2).unwrap();

        assert!(l.authorize(&SID, Capability::Clipboard, Persona::GooglePlay, Persona::Clean, NOW).is_ok());

        // Fan-out kill-switch signal: revoke every live consent, monotonically.
        let count = l.revoke_all("bridge kill-switch engaged");
        assert_eq!(count, 2);
        assert_eq!(
            l.authorize(&SID, Capability::Clipboard, Persona::GooglePlay, Persona::Clean, NOW),
            Err(ConsentError::Revoked)
        );
        assert_eq!(
            l.authorize(&SID, Capability::Files, Persona::GooglePlay, Persona::Clean, NOW),
            Err(ConsentError::Revoked)
        );

        // Idempotent: nothing left to newly revoke.
        assert_eq!(l.revoke_all("second call"), 0);
    }

    #[test]
    fn google_side_request_carries_no_signature_by_type() {
        // The far side can build a request — an ask — but the type has no signature
        // field and no way to mint one. This is a compile-time proof of "request,
        // never mint": if `ConsentRequest` ever grows a signer, this comment is the
        // canary. The near side answers by checking its own minted records.
        let req = ConsentRequest {
            session_id: SID,
            capability: Capability::Clipboard,
            direction: g2c(),
            peer_device: "peer".to_string(),
        };
        assert_eq!(req.capability, Capability::Clipboard);
    }
}
