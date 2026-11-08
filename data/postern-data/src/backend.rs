//! `StorageBackend` — the one seam between the trusted, offline, testable
//! world and the untrusted network.
//!
//! Spec: `docs/specs/POSTERN-DATA-FILECOIN-DESIGN.md`, §4. A backend takes
//! opaque ciphertext CARs and returns provider-reported CIDs (locators), and
//! answers persistence probes. Everything above this trait is deterministic,
//! panic-free, and offline-testable; everything below it is the untrusted
//! hosted-provider world.
//!
//! HONESTY (see crate docs): the live Lighthouse HTTP client is **gated behind
//! the `live` cargo feature**, so the DEFAULT build ships no network client at
//! all — the structural honesty gate is the labelled opt-in, not the absence
//! of an implementation. This module ships:
//!
//! * [`MockBackend`] — an in-memory test double (also the offline `DirBackend`
//!   analog for unit tests), with fault-injection helpers so callers can prove
//!   they re-verify provider bytes.
//! * [`LiveBackend`] — in the DEFAULT build, a documented SCAFFOLD stub whose
//!   methods are `todo!()` (calling any method panics), pinning the shape the
//!   real client must implement. Under `--features live` this name instead
//!   re-exports the **REAL Lighthouse client** from [`crate::live`] — an
//!   UNAUDITED, zero-dependency, hand-rolled HTTP/1.1 client that needs a local
//!   TLS-terminating proxy to reach the HTTPS hosts.
//!
//! Returned CIDs carry **zero integrity weight**: they are provider-reported
//! locators. A caller MUST re-hash fetched bytes against an out-of-band
//! SHAKE-256 digest before use — the DEFAULT build cannot do that (it has no
//! hashing); `--features hash` compiles the real `crate::hash::Shake256Hasher`
//! for exactly that re-verification.

/// The durable on-disk spool backend. See [`dir::DirBackend`].
pub mod dir;

pub use dir::DirBackend;

/// An opaque content locator returned by a backend.
///
/// For a real backend this is a CIDv1 (`0x01 ‖ codec ‖ 0x12 0x20 ‖
/// sha2-256[32]`); this crate never parses or trusts its structure. Two CIDs
/// are equal iff their bytes are equal. (The [`dir::DirBackend`] *does* compute
/// and re-verify this structure internally, as a content-address locator with
/// zero integrity weight — the PQ integrity story stays the separate SHAKE-256
/// overlay.)
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Cid(pub Vec<u8>);

impl Cid {
    /// Borrow the raw locator bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// One reported Filecoin deal for a stored object. All fields are
/// provider-reported and unverified by this crate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DealInfo {
    /// On-chain deal id, if the provider reports one (`None` while sealing).
    pub deal_id: Option<u64>,
    /// Storage-provider actor id (e.g. `f0…`).
    pub provider: String,
    /// Deal expiry epoch, if reported. Durability past this needs a re-deal
    /// (a Phase 4 monitor concern, not this crate's).
    pub end_epoch: Option<u64>,
}

/// Persistence probe result — honest vocabulary only (§6). `Acknowledged`
/// means the provider *claims* to hold the bytes in its hot layer; it is
/// **not** a Filecoin deal and must never be rendered as "backed up".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DealStatus {
    /// Provider unreachable, or no record of this CID.
    Unknown,
    /// Provider says it holds the bytes (HOT layer only — NOT a deal).
    Acknowledged,
    /// On-chain deals reported for this CID.
    DealActive(Vec<DealInfo>),
}

/// Typed backend failure. Never a panic in the offline impls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendError {
    /// No object stored under the given CID.
    NotFound,
    /// A hardened backend computed a client-side CID that disagreed with the
    /// provider's ack (the single-raw-block-CAR hardening of §4). The offline
    /// [`MockBackend`] can be told to raise this via
    /// [`MockBackend::fail_next_put_with`].
    CidMismatch,
    /// Transport / provider error (message is provider-reported, untrusted).
    Unavailable(String),
}

impl core::fmt::Display for BackendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound => write!(f, "backend: object not found"),
            Self::CidMismatch => write!(f, "backend: client CID disagrees with provider ack"),
            Self::Unavailable(m) => write!(f, "backend: unavailable: {m}"),
        }
    }
}

impl std::error::Error for BackendError {}

/// The pluggable storage seam. Synchronous, blocking, `Vec<u8>` in/out —
/// MVP blobs are whole CARs; streaming is a later concern. The live crate
/// wraps its async transport internally behind this sync trait.
pub trait StorageBackend {
    /// Upload an opaque ciphertext CAR. The returned [`Cid`] is
    /// PROVIDER-REPORTED and treated as a **locator** — it carries no
    /// integrity weight.
    fn put_car(&mut self, bytes: &[u8]) -> Result<Cid, BackendError>;

    /// Fetch by CID. The CALLER MUST verify a SHAKE-256 digest against the
    /// manifest before using the bytes; backend bytes are untrusted.
    fn get(&mut self, cid: &Cid) -> Result<Vec<u8>, BackendError>;

    /// Persistence probe for a stored CID.
    fn deal_status(&mut self, cid: &Cid) -> Result<DealStatus, BackendError>;
}

// ── MockBackend — in-memory test double ───────────────────────────────────────

use std::collections::HashMap;

/// In-memory [`StorageBackend`] for tests.
///
/// CIDs it returns are **synthetic** (`b"mock-cid:" ‖ counter`), NOT real
/// sha2-256 CIDs — this crate has no hashing. That is deliberate: the mock
/// exists to exercise the *seam and the caller's re-verification discipline*,
/// not to reproduce Filecoin addressing. Fault-injection helpers
/// ([`MockBackend::fail_next_put_with`], [`MockBackend::corrupt`],
/// [`MockBackend::set_deal_status`]) let callers prove they detect
/// substituted / unavailable bytes.
#[derive(Debug, Default)]
pub struct MockBackend {
    objects: HashMap<Vec<u8>, Vec<u8>>,
    deals: HashMap<Vec<u8>, DealStatus>,
    next_id: u64,
    fail_next_put: Option<BackendError>,
}

impl MockBackend {
    /// A fresh, empty mock.
    pub fn new() -> Self {
        Self::default()
    }

    /// Arm the next [`StorageBackend::put_car`] call to fail with `err`
    /// (e.g. [`BackendError::CidMismatch`] to model the hardened-CAR check,
    /// or [`BackendError::Unavailable`] to model a provider outage). Consumed
    /// by the next put.
    pub fn fail_next_put_with(&mut self, err: BackendError) {
        self.fail_next_put = Some(err);
    }

    /// Adversarially overwrite the bytes stored under `cid` (models a
    /// provider substituting content). A correct caller detects this by
    /// re-hashing on [`StorageBackend::get`]. No-op if the CID is unknown.
    pub fn corrupt(&mut self, cid: &Cid, replacement: Vec<u8>) {
        if let Some(slot) = self.objects.get_mut(&cid.0) {
            *slot = replacement;
        }
    }

    /// Set the persistence status a later [`StorageBackend::deal_status`]
    /// probe will report for `cid`.
    pub fn set_deal_status(&mut self, cid: &Cid, status: DealStatus) {
        self.deals.insert(cid.0.clone(), status);
    }
}

impl StorageBackend for MockBackend {
    fn put_car(&mut self, bytes: &[u8]) -> Result<Cid, BackendError> {
        if let Some(err) = self.fail_next_put.take() {
            return Err(err);
        }
        let mut key = b"mock-cid:".to_vec();
        key.extend_from_slice(&self.next_id.to_le_bytes());
        self.next_id = self.next_id.wrapping_add(1);
        self.objects.insert(key.clone(), bytes.to_vec());
        Ok(Cid(key))
    }

    fn get(&mut self, cid: &Cid) -> Result<Vec<u8>, BackendError> {
        self.objects.get(&cid.0).cloned().ok_or(BackendError::NotFound)
    }

    fn deal_status(&mut self, cid: &Cid) -> Result<DealStatus, BackendError> {
        if !self.objects.contains_key(&cid.0) {
            return Err(BackendError::NotFound);
        }
        Ok(self.deals.get(&cid.0).cloned().unwrap_or(DealStatus::Unknown))
    }
}

// ── RecordingBackend — scripted fault injection ───────────────────────────────

use std::collections::VecDeque;

/// One scripted adversarial fault for [`RecordingBackend`].
///
/// Each variant names the [`StorageBackend`] operation it targets. A fault is
/// consumed by the *next* call to its target operation; calls to other
/// operations pass through untouched and never consume it. This is the §4 /
/// Phase-2 fault menu — `CidMismatch`, truncated bytes, wrong bytes, and
/// drop-before-deal — the [`MockBackend`] one-shot helpers only partially
/// cover, gathered into an ordered script so a restore path can be driven
/// through a whole adversarial sequence offline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    /// Next [`StorageBackend::put_car`] fails with [`BackendError::CidMismatch`]
    /// (models the hardened single-raw-block-CAR check disagreeing with the
    /// provider ack). Nothing is stored.
    CidMismatch,
    /// Next [`StorageBackend::put_car`] fails with
    /// [`BackendError::Unavailable`] carrying this provider-reported message
    /// (models a transport / provider outage). Nothing is stored.
    PutUnavailable(String),
    /// Next [`StorageBackend::get`] returns the stored bytes truncated to
    /// `keep` bytes (models a short read / partial CAR). This is an
    /// **observable substitution**, not an error: the returned bytes differ
    /// from what was stored, so a caller re-hashing against the manifest's
    /// SHAKE-256 digest MUST reject them. `keep` past the stored length yields
    /// the whole object.
    Truncated { keep: usize },
    /// Next [`StorageBackend::get`] returns `replacement` instead of the stored
    /// bytes (models a provider swapping content). Also an observable
    /// substitution the caller's post-fetch SHAKE re-check must catch.
    WrongBytes(Vec<u8>),
    /// Next [`StorageBackend::get`] fails with [`BackendError::NotFound`] even
    /// though the object was stored (models the provider having dropped the
    /// bytes).
    GetDropped,
    /// Next [`StorageBackend::deal_status`] reports [`DealStatus::Unknown`],
    /// overriding any status previously set (models bytes dropped by the
    /// provider before any deal was made — the restore path must fail closed
    /// rather than claim "backed up").
    DropBeforeDeal,
}

impl Fault {
    /// Which operation this fault is consumed by. Used to decide whether the
    /// head-of-script fault applies to the operation currently running.
    fn target(&self) -> FaultTarget {
        match self {
            Self::CidMismatch | Self::PutUnavailable(_) => FaultTarget::Put,
            Self::Truncated { .. } | Self::WrongBytes(_) | Self::GetDropped => FaultTarget::Get,
            Self::DropBeforeDeal => FaultTarget::DealStatus,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FaultTarget {
    Put,
    Get,
    DealStatus,
}

/// A [`StorageBackend`] that replays a caller-scripted, ordered queue of
/// adversarial [`Fault`]s over an in-memory store.
///
/// It composes a [`MockBackend`] for the honest happy-path storage and
/// overlays the fault script on top. Faults are consumed **in order**, each by
/// the next call to its target operation ([`Fault::target`]); an operation
/// whose kind does not match the head-of-script fault runs normally and leaves
/// the script untouched. With an **empty script it round-trips byte-for-byte
/// like [`MockBackend`]** — that equivalence is the baseline the fault
/// variants deviate from.
///
/// Every applied fault is recorded (see [`RecordingBackend::applied`]) so a
/// test can assert the exact adversarial sequence the caller was subjected to.
///
/// SCAFFOLD / UNAUDITED test double: it stores nothing durable, computes no
/// hashes, and proves nothing about the live path. Its sole purpose is to
/// drive the caller's mandatory post-fetch SHAKE re-check and restore
/// fail-closed paths through adversarial inputs, entirely offline.
#[derive(Debug, Default)]
pub struct RecordingBackend {
    inner: MockBackend,
    script: VecDeque<Fault>,
    applied: Vec<Fault>,
}

impl RecordingBackend {
    /// A fresh backend with an empty script (round-trips like [`MockBackend`]).
    pub fn new() -> Self {
        Self::default()
    }

    /// A backend pre-loaded with an ordered fault script.
    pub fn with_script(faults: impl IntoIterator<Item = Fault>) -> Self {
        Self {
            inner: MockBackend::new(),
            script: faults.into_iter().collect(),
            applied: Vec::new(),
        }
    }

    /// Append one fault to the end of the script.
    pub fn push_fault(&mut self, fault: Fault) {
        self.script.push_back(fault);
    }

    /// Number of faults still queued (not yet applied).
    pub fn remaining(&self) -> usize {
        self.script.len()
    }

    /// The faults that have been applied so far, in the order they fired.
    pub fn applied(&self) -> &[Fault] {
        &self.applied
    }

    /// Set the persistence status a later [`StorageBackend::deal_status`] probe
    /// reports for `cid` (unless overridden by a [`Fault::DropBeforeDeal`]).
    pub fn set_deal_status(&mut self, cid: &Cid, status: DealStatus) {
        self.inner.set_deal_status(cid, status);
    }

    /// Pop the head-of-script fault iff it targets `target`.
    fn take_if(&mut self, target: FaultTarget) -> Option<Fault> {
        if self.script.front().map(Fault::target) == Some(target) {
            let fault = self.script.pop_front().expect("front checked above");
            self.applied.push(fault.clone());
            Some(fault)
        } else {
            None
        }
    }
}

impl StorageBackend for RecordingBackend {
    fn put_car(&mut self, bytes: &[u8]) -> Result<Cid, BackendError> {
        match self.take_if(FaultTarget::Put) {
            Some(Fault::CidMismatch) => Err(BackendError::CidMismatch),
            Some(Fault::PutUnavailable(msg)) => Err(BackendError::Unavailable(msg)),
            _ => self.inner.put_car(bytes),
        }
    }

    fn get(&mut self, cid: &Cid) -> Result<Vec<u8>, BackendError> {
        match self.take_if(FaultTarget::Get) {
            Some(Fault::Truncated { keep }) => {
                let mut bytes = self.inner.get(cid)?;
                bytes.truncate(keep);
                Ok(bytes)
            }
            Some(Fault::WrongBytes(replacement)) => {
                // The object must exist for the substitution to model a real
                // provider swap; surface NotFound honestly if it does not.
                self.inner.get(cid)?;
                Ok(replacement)
            }
            Some(Fault::GetDropped) => Err(BackendError::NotFound),
            _ => self.inner.get(cid),
        }
    }

    fn deal_status(&mut self, cid: &Cid) -> Result<DealStatus, BackendError> {
        match self.take_if(FaultTarget::DealStatus) {
            Some(Fault::DropBeforeDeal) => {
                // The CID must still be a known object; a probe for an unknown
                // CID is NotFound, drop-before-deal or not.
                if self.inner.deal_status(cid).is_err() {
                    return Err(BackendError::NotFound);
                }
                Ok(DealStatus::Unknown)
            }
            _ => self.inner.deal_status(cid),
        }
    }
}

// ── LiveBackend ───────────────────────────────────────────────────────────────

/// SCAFFOLD stub for the live hosted-provider backend — present ONLY in the
/// default (no-`live`) build, where this crate deliberately has no network
/// client (the structural honesty gate).
///
/// // SCAFFOLD: enable the `live` cargo feature to replace this stub with the
/// // REAL Lighthouse client in [`crate::live::LiveBackend`] (re-exported here
/// // under `--features live`). Without that feature every method is `todo!()`;
/// // this type exists only to pin the trait shape and to keep the default
/// // build network-incapable — it stores nothing and proves nothing.
#[cfg(not(feature = "live"))]
#[derive(Debug, Default)]
pub struct LiveBackend {
    /// Provider base URL / config placeholder (unused in the stub).
    pub endpoint: String,
}

#[cfg(not(feature = "live"))]
impl StorageBackend for LiveBackend {
    fn put_car(&mut self, _bytes: &[u8]) -> Result<Cid, BackendError> {
        todo!("SCAFFOLD: enable the `live` feature for the real Lighthouse client (crate::live)")
    }

    fn get(&mut self, _cid: &Cid) -> Result<Vec<u8>, BackendError> {
        todo!("SCAFFOLD: enable the `live` feature for the real Lighthouse client (crate::live)")
    }

    fn deal_status(&mut self, _cid: &Cid) -> Result<DealStatus, BackendError> {
        todo!("SCAFFOLD: enable the `live` feature for the real Lighthouse client (crate::live)")
    }
}

/// With `--features live`, the REAL Lighthouse client from [`crate::live`] is
/// re-exported under this name, so `backend::LiveBackend` resolves to a working
/// client while the default build keeps the `todo!()` scaffold above.
#[cfg(feature = "live")]
pub use crate::live::LiveBackend;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_then_get_round_trips() {
        let mut be = MockBackend::new();
        let cid = be.put_car(b"sealed-ciphertext-bytes").unwrap();
        assert_eq!(be.get(&cid).unwrap(), b"sealed-ciphertext-bytes");
    }

    #[test]
    fn distinct_puts_get_distinct_cids() {
        let mut be = MockBackend::new();
        let a = be.put_car(b"aaaa").unwrap();
        let b = be.put_car(b"bbbb").unwrap();
        assert_ne!(a, b);
        assert_eq!(be.get(&a).unwrap(), b"aaaa");
        assert_eq!(be.get(&b).unwrap(), b"bbbb");
    }

    #[test]
    fn get_unknown_cid_is_not_found() {
        let mut be = MockBackend::new();
        assert_eq!(be.get(&Cid(b"nope".to_vec())), Err(BackendError::NotFound));
    }

    #[test]
    fn fail_next_put_is_one_shot() {
        let mut be = MockBackend::new();
        be.fail_next_put_with(BackendError::CidMismatch);
        assert_eq!(be.put_car(b"x"), Err(BackendError::CidMismatch));
        // The arming is consumed: the next put succeeds.
        assert!(be.put_car(b"x").is_ok());
    }

    #[test]
    fn corrupt_models_provider_substitution() {
        // The seam's whole point: get() bytes are untrusted. The mock lets a
        // test simulate a provider swapping content; a correct caller catches
        // it by re-hashing (out of scope here, but the substitution is
        // observable at the seam).
        let mut be = MockBackend::new();
        let cid = be.put_car(b"honest-bytes").unwrap();
        be.corrupt(&cid, b"evil-bytes".to_vec());
        assert_eq!(be.get(&cid).unwrap(), b"evil-bytes");
    }

    #[test]
    fn deal_status_reports_set_status() {
        let mut be = MockBackend::new();
        let cid = be.put_car(b"data").unwrap();
        assert_eq!(be.deal_status(&cid).unwrap(), DealStatus::Unknown);
        let deals = vec![DealInfo {
            deal_id: Some(42),
            provider: "f01234".to_string(),
            end_epoch: Some(5_000_000),
        }];
        be.set_deal_status(&cid, DealStatus::DealActive(deals.clone()));
        assert_eq!(be.deal_status(&cid).unwrap(), DealStatus::DealActive(deals));
    }

    #[test]
    fn deal_status_unknown_cid_is_not_found() {
        let mut be = MockBackend::new();
        assert_eq!(
            be.deal_status(&Cid(b"ghost".to_vec())),
            Err(BackendError::NotFound)
        );
    }

    // Default build only: the LiveBackend scaffold panics until the `live`
    // feature swaps in the real client. Under `--features live` this stub (and
    // this test) do not exist; the real client is exercised in `crate::live`.
    #[cfg(not(feature = "live"))]
    #[test]
    #[should_panic(expected = "SCAFFOLD")]
    fn live_backend_put_is_todo() {
        let mut be = LiveBackend::default();
        let _ = be.put_car(b"x");
    }

    // ── RecordingBackend ──────────────────────────────────────────────────

    #[test]
    fn empty_script_round_trips_like_mock() {
        // Acceptance: with an empty script the RecordingBackend must behave
        // byte-for-byte like a MockBackend across the whole seam.
        let mut rec = RecordingBackend::new();
        let mut mock = MockBackend::new();

        let rec_a = rec.put_car(b"alpha").unwrap();
        let mock_a = mock.put_car(b"alpha").unwrap();
        // Synthetic CIDs are derived identically (same counter start).
        assert_eq!(rec_a, mock_a);

        let rec_b = rec.put_car(b"beta").unwrap();
        let mock_b = mock.put_car(b"beta").unwrap();
        assert_eq!(rec_b, mock_b);

        assert_eq!(rec.get(&rec_a).unwrap(), mock.get(&mock_a).unwrap());
        assert_eq!(rec.get(&rec_b).unwrap(), mock.get(&mock_b).unwrap());
        assert_eq!(
            rec.get(&Cid(b"nope".to_vec())),
            mock.get(&Cid(b"nope".to_vec()))
        );
        assert_eq!(rec.deal_status(&rec_a), mock.deal_status(&mock_a));

        assert_eq!(rec.remaining(), 0);
        assert!(rec.applied().is_empty());
    }

    #[test]
    fn scripted_faults_surface_in_order() {
        // Acceptance: a caller-scripted queue of faults — Truncated bytes,
        // WrongBytes substitution, CidMismatch, and drop-before-deal — each
        // surfaces as the expected BackendError or observable substitution,
        // consumed strictly in the scripted order.
        let mut rec = RecordingBackend::with_script([
            Fault::CidMismatch,
            Fault::Truncated { keep: 3 },
            Fault::WrongBytes(b"evil".to_vec()),
            Fault::GetDropped,
            Fault::DropBeforeDeal,
        ]);

        // 1. CidMismatch: the first put fails, stores nothing.
        assert_eq!(rec.put_car(b"honest-ciphertext"), Err(BackendError::CidMismatch));

        // A genuine put (no put-fault at the head now) succeeds and stores.
        let cid = rec.put_car(b"honest-ciphertext").unwrap();

        // 2. Truncated: observable substitution — shorter than what we stored.
        assert_eq!(rec.get(&cid).unwrap(), b"hon");

        // 3. WrongBytes: observable substitution — different content entirely.
        assert_eq!(rec.get(&cid).unwrap(), b"evil");

        // 4. drop-before-deal, get side: the object reads as gone.
        assert_eq!(rec.get(&cid), Err(BackendError::NotFound));

        // A pre-set DealActive baseline is overridden by DropBeforeDeal.
        rec.set_deal_status(
            &cid,
            DealStatus::DealActive(vec![DealInfo {
                deal_id: Some(7),
                provider: "f01234".to_string(),
                end_epoch: Some(9_000_000),
            }]),
        );
        // 5. drop-before-deal, probe side: fails closed to Unknown, never a deal.
        assert_eq!(rec.deal_status(&cid).unwrap(), DealStatus::Unknown);

        // Every fault fired exactly once, in the scripted order.
        assert_eq!(rec.remaining(), 0);
        assert_eq!(
            rec.applied(),
            &[
                Fault::CidMismatch,
                Fault::Truncated { keep: 3 },
                Fault::WrongBytes(b"evil".to_vec()),
                Fault::GetDropped,
                Fault::DropBeforeDeal,
            ]
        );
    }

    #[test]
    fn put_unavailable_fault_surfaces_and_stores_nothing() {
        let mut rec = RecordingBackend::with_script([Fault::PutUnavailable("tor down".into())]);
        assert_eq!(
            rec.put_car(b"bytes"),
            Err(BackendError::Unavailable("tor down".to_string()))
        );
        // Nothing was stored: the next honest put gets the first synthetic CID.
        let cid = rec.put_car(b"bytes").unwrap();
        assert_eq!(rec.get(&cid).unwrap(), b"bytes");
    }

    #[test]
    fn non_matching_op_does_not_consume_head_fault() {
        // The head fault targets get(); a put() in front of it must run
        // normally and leave the fault queued for the eventual get().
        let mut rec = RecordingBackend::with_script([Fault::WrongBytes(b"swapped".to_vec())]);
        let cid = rec.put_car(b"original").unwrap(); // put does not consume the get-fault
        assert_eq!(rec.remaining(), 1);
        assert_eq!(rec.get(&cid).unwrap(), b"swapped"); // now consumed
        assert_eq!(rec.remaining(), 0);
        // Fault spent: a second get returns the honest stored bytes.
        assert_eq!(rec.get(&cid).unwrap(), b"original");
    }

    #[test]
    fn truncate_past_length_yields_whole_object() {
        let mut rec = RecordingBackend::with_script([Fault::Truncated { keep: 999 }]);
        let cid = rec.put_car(b"short").unwrap();
        assert_eq!(rec.get(&cid).unwrap(), b"short");
    }

    #[test]
    fn wrong_bytes_on_unknown_cid_is_not_found() {
        // The substitution models a provider swap of an object we actually
        // stored; probing an unknown CID must still fail closed as NotFound.
        let mut rec = RecordingBackend::with_script([Fault::WrongBytes(b"x".to_vec())]);
        assert_eq!(rec.get(&Cid(b"ghost".to_vec())), Err(BackendError::NotFound));
    }

    #[test]
    fn drop_before_deal_on_unknown_cid_is_not_found() {
        let mut rec = RecordingBackend::with_script([Fault::DropBeforeDeal]);
        assert_eq!(
            rec.deal_status(&Cid(b"ghost".to_vec())),
            Err(BackendError::NotFound)
        );
    }

    #[test]
    fn push_fault_appends_to_script() {
        let mut rec = RecordingBackend::new();
        rec.push_fault(Fault::CidMismatch);
        rec.push_fault(Fault::Truncated { keep: 1 });
        assert_eq!(rec.remaining(), 2);
        assert_eq!(rec.put_car(b"x"), Err(BackendError::CidMismatch));
        let cid = rec.put_car(b"yy").unwrap();
        assert_eq!(rec.get(&cid).unwrap(), b"y");
    }
}
