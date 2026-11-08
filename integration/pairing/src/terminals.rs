// SPDX-License-Identifier: MIT OR Apache-2.0
//! # Paired terminals — the managed, sealed-at-rest collection of records
//!
//! ## ⚠️ SCAFFOLD — not a secure, audited, or deployed system
//!
//! v1 proved the ceremony and the primitives; it left a wiring gap the phone
//! side needs: `confirm_sas` yields a single [`PairingRecord`] in RAM, and
//! [`persist`], [`seal`], and [`resume`] each work in isolation, but nothing
//! ties them into the **collection** a "paired terminals" screen manages — the
//! list of every laptop this phone has paired, each sealed at rest, each with a
//! one-tap **revoke**, and a **panic-revoke** that evicts them all at once.
//!
//! [`PairedTerminals`] is that seam. It closes the v2 gaps:
//!
//! - **Persist-on-pair** — [`PairedTerminals::add`] seals a freshly
//!   SAS-confirmed record with the storage KEK (`postern-vault` on desktop,
//!   StrongBox/SE-wrapped on mobile) and stores the blob. This is the
//!   `confirm_sas` → persistence wiring v1 lacked.
//! - **Monotonic revoke** — [`PairedTerminals::revoke`] wipes the record in RAM
//!   ([`PairingRecord::revoke`]) and then **deletes** the sealed blob. There is
//!   no un-revoke because [`persist::save`] refuses to re-seal a revoked record
//!   by design (`PersistError::Revoked`): the contract is *delete*, and a
//!   deleted blob cannot be resurrected.
//! - **Panic-revoke** — [`PairedTerminals::panic_revoke_all`] evicts every
//!   paired terminal at once. This is the hook a `postern-panic` re-lock calls
//!   so a duress lock also drops every reconnect-without-SAS channel; after it,
//!   no terminal can resume without a fresh 6-digit SAS ceremony.
//! - **Forward-secret resume** — [`PairedTerminals::begin_resume`] /
//!   [`PairedTerminals::accept_resume`] drive [`resume`] from a stored terminal,
//!   the reconnect-without-re-SAS path (still fail-closed on an identity-key
//!   rotation or binding change — those force a fresh SAS).
//!
//! ## Where the bytes live — the [`RecordStore`] seam
//!
//! This crate stays storage-agnostic (mirroring the [`transport`](crate::transport)
//! `Transport`/`Discovery` seams): where the sealed blobs rest is a trait. The
//! Dev/app layer plugs in `postern-vault` (desktop) or a StrongBox/SE-wrapped
//! store (mobile). An in-memory [`MemStore`] is provided for tests and demos.
//!
//! ## Honest limits (carried from [`record`](crate::record))
//!
//! - The pin trusts the device you scanned, **not** that its software is
//!   genuine — a software SHA-256 pin is tamper-evidence, not attestation.
//! - The storage KEK's hardware protection is the store's job, not this
//!   module's. On community-edition software keystores it is "hardware-assisted
//!   at rest" only where the platform provides it — stated, never assumed.

use zeroize::Zeroizing;

use crate::persist::{self, PersistError};
use crate::record::{PairingRecord, Role};
use crate::resume::{Resume, ResumeAccept, ResumeError, ResumeOffer, ResumePending};
use crate::channel::Channel;

/// A stable, **non-secret** identifier for one paired terminal, derived from the
/// pairing's channel binding (`SHA-256(nonce ‖ anchor_pubkey)`). Safe to show in
/// a UI and to use as a storage key — it carries no key material.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TerminalId(pub String);

impl core::fmt::Display for TerminalId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A UI-safe summary of one paired terminal. Carries **no** secret: never the
/// `session_root`, never the raw pinned key — only a short display fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalInfo {
    /// Stable id (channel-binding-derived).
    pub id: TerminalId,
    /// Human label for the peer ("Tiago's ThinkPad"). Cosmetic.
    pub nickname: String,
    /// This device's role in the pair (phone = Custodian, laptop = Terminal).
    pub role: Role,
    /// Short display fingerprint of the pinned peer identity key
    /// (`SHA-256(peer_identity_pub)`, first 8 bytes) for the human to compare —
    /// NOT the key itself.
    pub peer_pin_fpr: String,
    /// Whether this record is revoked. Always `false` for a *stored* terminal
    /// (revoke deletes the blob), present for completeness.
    pub revoked: bool,
}

/// Errors from the paired-terminals manager, parameterised over the backing
/// store's own error type.
#[derive(Debug, PartialEq, Eq)]
pub enum TerminalsError<E> {
    /// The backing store failed (I/O, keystore, etc.).
    Store(E),
    /// Seal/unseal or record validation failed — fail-closed.
    Persist(PersistError),
    /// A resume ceremony failed.
    Resume(ResumeError),
    /// No terminal with that id is stored.
    NotFound,
}

impl<E> From<PersistError> for TerminalsError<E> {
    fn from(e: PersistError) -> Self {
        TerminalsError::Persist(e)
    }
}
impl<E> From<ResumeError> for TerminalsError<E> {
    fn from(e: ResumeError) -> Self {
        TerminalsError::Resume(e)
    }
}

impl<E: core::fmt::Debug> core::fmt::Display for TerminalsError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TerminalsError::Store(e) => write!(f, "record store error: {e:?}"),
            TerminalsError::Persist(e) => write!(f, "{e}"),
            TerminalsError::Resume(e) => write!(f, "{e}"),
            TerminalsError::NotFound => write!(f, "no such paired terminal"),
        }
    }
}

/// Where sealed [`PairingRecord`] blobs rest. The Dev/app layer supplies the
/// concrete store: `postern-vault` on desktop, StrongBox/SE-wrapped on mobile.
/// This crate only seals/opens and never sees plaintext at rest.
pub trait RecordStore {
    /// The store's own error type.
    type Error;

    /// Insert or overwrite the sealed blob for `id`.
    fn put(&mut self, id: &TerminalId, sealed: &[u8]) -> Result<(), Self::Error>;
    /// Fetch the sealed blob for `id`, if present.
    fn get(&self, id: &TerminalId) -> Result<Option<Vec<u8>>, Self::Error>;
    /// Delete the sealed blob for `id` (idempotent — deleting a missing id is Ok).
    fn delete(&mut self, id: &TerminalId) -> Result<(), Self::Error>;
    /// All stored ids.
    fn ids(&self) -> Result<Vec<TerminalId>, Self::Error>;
}

/// The managed collection of sealed paired-terminal records.
///
/// Holds the 32-byte storage KEK (zeroized on drop) and the pluggable store.
/// Every record is sealed under this KEK bound to
/// [`persist::RECORD_CONTEXT`](crate::persist::RECORD_CONTEXT).
pub struct PairedTerminals<S: RecordStore> {
    store: S,
    storage_key: Zeroizing<[u8; 32]>,
}

impl<S: RecordStore> PairedTerminals<S> {
    /// Build a manager over `store`, sealing with `storage_key` (the KEK the
    /// platform keystore released). The KEK's Rust-side copy is wiped on drop.
    pub fn new(store: S, storage_key: [u8; 32]) -> Self {
        PairedTerminals { store, storage_key: Zeroizing::new(storage_key) }
    }

    /// The stable, non-secret id for a record (channel-binding-derived).
    pub fn id_for(record: &PairingRecord) -> TerminalId {
        // The channel binding is already SHA-256(nonce ‖ anchor_pubkey); a hex
        // prefix is a compact, collision-resistant-enough display/key id.
        TerminalId(hex(&record.channel_binding[..8]))
    }

    /// Seal a freshly SAS-confirmed record and persist it (the persist-on-pair
    /// wiring). Refuses a revoked record. Returns the stable id.
    pub fn add(&mut self, record: &PairingRecord) -> Result<TerminalId, TerminalsError<S::Error>> {
        if record.is_revoked() {
            return Err(PersistError::Revoked.into());
        }
        let id = Self::id_for(record);
        let sealed = persist::save(record, &self.storage_key)?;
        self.store.put(&id, &sealed).map_err(TerminalsError::Store)?;
        Ok(id)
    }

    /// Load and unseal one record (for a resume). Fail-closed on tamper/wrong key.
    pub fn load(&self, id: &TerminalId) -> Result<PairingRecord, TerminalsError<S::Error>> {
        let sealed = self
            .store
            .get(id)
            .map_err(TerminalsError::Store)?
            .ok_or(TerminalsError::NotFound)?;
        Ok(persist::load(&sealed, &self.storage_key)?)
    }

    /// UI-safe summaries of every stored terminal. A blob that fails to open
    /// (tampered / wrong KEK) is **omitted** — the trusted list never shows a
    /// record it cannot cryptographically vouch for (fail-closed).
    pub fn list(&self) -> Result<Vec<TerminalInfo>, TerminalsError<S::Error>> {
        let mut out = Vec::new();
        for id in self.store.ids().map_err(TerminalsError::Store)? {
            let Some(sealed) = self.store.get(&id).map_err(TerminalsError::Store)? else {
                continue;
            };
            if let Ok(rec) = persist::load(&sealed, &self.storage_key) {
                out.push(TerminalInfo {
                    id,
                    nickname: rec.nickname.clone(),
                    role: rec.role,
                    peer_pin_fpr: peer_fpr(&rec.peer_identity_pub),
                    revoked: rec.is_revoked(),
                });
            }
        }
        Ok(out)
    }

    /// Monotonic revoke of one terminal: wipe the record in RAM, then **delete**
    /// the sealed blob. There is no un-revoke — [`persist::save`] refuses to
    /// re-seal a revoked record, so the only correct action is deletion.
    pub fn revoke(&mut self, id: &TerminalId) -> Result<(), TerminalsError<S::Error>> {
        // Load first so a missing id is a clean NotFound (and so a tampered blob
        // is caught fail-closed before we claim to have revoked anything).
        let mut rec = self.load(id)?;
        rec.revoke(); // wipes session_root + pin in RAM; blob removed next
        self.store.delete(id).map_err(TerminalsError::Store)?;
        Ok(())
    }

    /// Panic-revoke: evict **every** paired terminal. The hook a `postern-panic`
    /// re-lock calls so a duress lock also drops all reconnect channels. Returns
    /// how many terminals were evicted. After this, every terminal needs a fresh
    /// SAS ceremony to pair again.
    pub fn panic_revoke_all(&mut self) -> Result<usize, TerminalsError<S::Error>> {
        let ids = self.store.ids().map_err(TerminalsError::Store)?;
        let n = ids.len();
        for id in &ids {
            self.store.delete(id).map_err(TerminalsError::Store)?;
        }
        Ok(n)
    }

    /// Begin a forward-secret resume for a stored terminal (custodian side):
    /// no re-SAS, fail-closed on a pin mismatch. Pair with
    /// [`ResumePending::finish`] once the peer's [`ResumeAccept`] arrives.
    pub fn begin_resume(
        &self,
        id: &TerminalId,
    ) -> Result<(ResumePending, ResumeOffer), TerminalsError<S::Error>> {
        let rec = self.load(id)?;
        Ok(Resume::offer(&rec)?)
    }

    /// Accept a peer's resume offer for a stored terminal (terminal side):
    /// yields the live [`Channel`] plus the [`ResumeAccept`] to send back.
    pub fn accept_resume(
        &self,
        id: &TerminalId,
        offer: &ResumeOffer,
    ) -> Result<(Channel, ResumeAccept), TerminalsError<S::Error>> {
        let rec = self.load(id)?;
        Ok(Resume::accept(&rec, offer)?)
    }

    /// Read-only access to the backing store (for the app layer's own needs).
    pub fn store(&self) -> &S {
        &self.store
    }
}

/// Lowercase-hex encode.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// Short display fingerprint of a pinned peer identity key. Groups the first 8
/// bytes of `SHA-256(peer_identity_pub)` for human comparison — never the key.
fn peer_fpr(peer_identity_pub: &[u8]) -> String {
    if peer_identity_pub.is_empty() {
        return "(revoked)".to_string();
    }
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(peer_identity_pub);
    let h = hex(&d[..8]).to_uppercase();
    // "AB12-CD34-EF56-7890"
    format!("{}-{}-{}-{}", &h[0..4], &h[4..8], &h[8..12], &h[12..16])
}

/// An in-memory [`RecordStore`] for tests and demos. NOT sealed at rest itself —
/// it holds the already-sealed blobs, which is the whole point (plaintext never
/// touches the store). A real deployment uses `postern-vault` / StrongBox.
#[derive(Default)]
pub struct MemStore {
    map: std::collections::BTreeMap<TerminalId, Vec<u8>>,
}

impl MemStore {
    /// A new empty in-memory store.
    pub fn new() -> Self {
        MemStore { map: std::collections::BTreeMap::new() }
    }
    /// How many sealed blobs are held.
    pub fn len(&self) -> usize {
        self.map.len()
    }
    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl RecordStore for MemStore {
    type Error = core::convert::Infallible;

    fn put(&mut self, id: &TerminalId, sealed: &[u8]) -> Result<(), Self::Error> {
        self.map.insert(id.clone(), sealed.to_vec());
        Ok(())
    }
    fn get(&self, id: &TerminalId) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.map.get(id).cloned())
    }
    fn delete(&mut self, id: &TerminalId) -> Result<(), Self::Error> {
        self.map.remove(id);
        Ok(())
    }
    fn ids(&self) -> Result<Vec<TerminalId>, Self::Error> {
        Ok(self.map.keys().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::BINDING_LEN;
    use crate::hybrid::SESSION_KEY_LEN;

    fn record(nickname: &str, pin: &[u8], binding_seed: u8) -> PairingRecord {
        PairingRecord::new(
            Role::Terminal,
            nickname,
            pin.to_vec(),
            [binding_seed; BINDING_LEN],
            Zeroizing::new([binding_seed.wrapping_add(1); SESSION_KEY_LEN]),
        )
    }

    fn manager() -> PairedTerminals<MemStore> {
        PairedTerminals::new(MemStore::new(), [7u8; 32])
    }

    #[test]
    fn add_then_list_roundtrips_without_leaking_secrets() {
        let mut pt = manager();
        let id = pt.add(&record("Tiago's ThinkPad", &[1, 2, 3, 4], 9)).unwrap();

        let list = pt.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, id);
        assert_eq!(list[0].nickname, "Tiago's ThinkPad");
        assert_eq!(list[0].role, Role::Terminal);
        assert!(!list[0].revoked);
        // The summary must not carry the raw pin or any session material.
        assert!(!list[0].peer_pin_fpr.is_empty());
        assert_ne!(list[0].peer_pin_fpr, "(revoked)");
    }

    #[test]
    fn id_is_stable_and_derived_from_binding() {
        let r = record("x", &[9], 42);
        assert_eq!(PairedTerminals::<MemStore>::id_for(&r), PairedTerminals::<MemStore>::id_for(&r));
    }

    #[test]
    fn revoke_deletes_the_blob_and_is_monotonic() {
        let mut pt = manager();
        let id = pt.add(&record("laptop", &[5, 5, 5], 3)).unwrap();
        assert_eq!(pt.store().len(), 1);

        pt.revoke(&id).unwrap();
        // The sealed blob is GONE — not rewritten as "revoked".
        assert_eq!(pt.store().len(), 0);
        assert!(pt.list().unwrap().is_empty());
        // Re-revoking a now-absent terminal is a clean NotFound (no un-revoke,
        // nothing to resurrect).
        assert_eq!(pt.revoke(&id), Err(TerminalsError::NotFound));
    }

    #[test]
    fn panic_revoke_evicts_everything() {
        let mut pt = manager();
        pt.add(&record("a", &[1], 1)).unwrap();
        pt.add(&record("b", &[2], 2)).unwrap();
        pt.add(&record("c", &[3], 3)).unwrap();
        assert_eq!(pt.store().len(), 3);

        let n = pt.panic_revoke_all().unwrap();
        assert_eq!(n, 3);
        assert_eq!(pt.store().len(), 0);
        assert!(pt.list().unwrap().is_empty());
    }

    #[test]
    fn load_missing_is_not_found() {
        let pt = manager();
        assert_eq!(pt.load(&TerminalId("deadbeef".into())).err(), Some(TerminalsError::NotFound));
    }

    #[test]
    fn a_tampered_blob_is_omitted_from_the_trusted_list_and_fails_load() {
        let mut pt = manager();
        let id = pt.add(&record("laptop", &[7, 7], 4)).unwrap();
        // Corrupt the sealed blob in place.
        let mut bad = pt.store().get(&id).unwrap().unwrap();
        let n = bad.len();
        bad[n / 2] ^= 0xff;
        pt.store.put(&id, &bad).unwrap();

        // Fail-closed: it neither lists nor loads.
        assert!(pt.list().unwrap().is_empty());
        assert!(matches!(pt.load(&id), Err(TerminalsError::Persist(PersistError::Seal))));
    }

    #[test]
    fn wrong_storage_key_cannot_open() {
        // Seal under one KEK…
        let mut a = PairedTerminals::new(MemStore::new(), [1u8; 32]);
        let id = a.add(&record("laptop", &[9, 9], 6)).unwrap();
        let sealed = a.store().get(&id).unwrap().unwrap();

        // …and try to open under a different KEK: fail-closed.
        let mut store = MemStore::new();
        store.put(&id, &sealed).unwrap();
        let b = PairedTerminals::new(store, [2u8; 32]);
        assert!(matches!(b.load(&id), Err(TerminalsError::Persist(PersistError::Seal))));
        assert!(b.list().unwrap().is_empty());
    }
}
