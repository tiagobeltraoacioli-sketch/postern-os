//! Offline anchor ↔ package binding checks (the non-PQ legs of verify).
//!
//! Spec: `docs/specs/POSTERN-DATA-FILECOIN-DESIGN.md`, §1 ("recompute the
//! manifest_root, compare it to the anchor") and §3.2. This module answers two
//! narrow, offline-decidable questions through the [`Hasher`] seam, and only
//! these:
//!
//! > 1. Does the [`Package`] a reader fetched actually hash to the
//! >    `manifest_root` the [`AnchorEnvelope`] committed on-chain?
//! >    ([`bind_anchor_to_package`])
//! > 2. Does the [`Package`]'s `pk` recompute to the `signer_commit` the
//! >    [`AnchorEnvelope`] committed on-chain? ([`bind_signer_to_commit`])
//!
//! It recomputes the root through the [`Hasher`] seam — `hasher.manifest_root(
//! &package)`, i.e. `digest(DOMAIN_MANIFEST_ROOT, package.committed_prefix())`
//! — and compares it, constant-shape, to [`AnchorEnvelope::manifest_root`]. A
//! mismatch is the typed [`VerifyError::RootMismatch`]; agreement is `Ok(())`.
//! Because the root is taken over the package's **committed prefix**
//! ([`Package::committed_prefix`] — magic, version, tier, salt and the whole
//! sealed manifest), this binding transitively covers the salt and `kdf_tier`
//! (tampering either changes the root) but is, by construction, **independent
//! of the trailing `pk`/`sig`** (those are signed *over* the root, not *into*
//! it).
//!
//! ## What this is NOT — the gated PQ leg (LOUD)
//!
//! **This is only the OFFLINE HALF of verification, and it establishes NO
//! authenticity whatsoever.** A [`RootMismatch`]-free result means *"these
//! bytes are the bytes this anchor points at"* and nothing more. It is NOT a
//! signature check, and a permissionless fee-payer can anchor any
//! `(manifest_root, signer_commit, package)` triple they like — a passing
//! binding on an *attacker-authored* anchor+package still passes. Two things
//! that DO establish authenticity are **deliberately NOT performed here**
//! (they need real crypto — `bloch-crypto` / a real SHA3 + the PQ verifier —
//! which is structurally out of this zero-dep crate's honesty scope). They are
//! no longer merely hypothetical, though: both are now REALLY implemented in
//! `postern-backup-net` (`signer::verify_signed_backup`), which composes the
//! two offline legs below under the real `Shake256Hasher` with a real
//! ML-DSA-65‖Falcon-1024 signature verification. What remains true is that
//! *this* crate, on its own, runs neither:
//!
//! 1. **The PQ signature leg is NOT checked here.** Nobody in this crate
//!    verifies the ML-DSA-65‖Falcon-1024 hybrid signature ([`Package::sig`])
//!    over [`AnchorEnvelope::signing_transcript`]; that verification lives in
//!    `postern-backup-net`. Absent it, an [`AnchorEnvelope`] decoded by this
//!    crate is an unauthenticated *claim*.
//! 2. **The `signer_commit` check is WIRED, but its real hash is NOT run.**
//!    [`bind_signer_to_commit`] now binds [`AnchorEnvelope::signer_commit`] to
//!    [`Package::pk`] through the [`Hasher`] seam — but this is the **offline
//!    wiring half only**. The real commitment is `SHA3-256(pk)`, and this crate
//!    runs no real hash: the in-crate [`Hasher`] impl is the
//!    ZERO-collision-resistance [`crate::hash::MockHasher`], explicitly **NOT**
//!    SHA3/SHAKE. So a passing signer-binding here proves the fetched `pk` maps
//!    to the anchor's committed value *under the mock*, and says **nothing**
//!    about the real signer's identity until a real `SHA3-256`
//!    [`Hasher::signer_commit`] adapter plugs in behind `postern-backup-net`.
//!    (And even a real SHA3 match only ties `pk` to the anchor — it is the PQ
//!    signature leg (1), still gated, that proves that `pk` actually signed.)
//!
//! The [`Hasher`] passed in is, in every in-crate test, the [`MockHasher`] —
//! **not** SHAKE-256, **not** SHA3-256 — so a passing check in this crate's
//! tests is a statement about wiring, never about cryptographic integrity. Real
//! `SHAKE-256/256(DOMAIN_MANIFEST_ROOT ‖ committed_prefix)`, real
//! `SHA3-256(pk)`, and the gated PQ signature leg plug in behind the
//! `postern-backup-net` boundary. See the crate docs' honesty scope.
//!
//! [`RootMismatch`]: VerifyError::RootMismatch
//! [`SignerMismatch`]: VerifyError::SignerMismatch
//! [`MockHasher`]: crate::hash::MockHasher

use crate::anchor::AnchorEnvelope;
use crate::hash::Hasher;
use crate::package::{Package, PackageError};

/// Typed failure of the offline binding checks.
///
/// Deliberately small: each binding function makes exactly one comparison, so
/// there is exactly one "bound bytes don't match" outcome per leg —
/// [`VerifyError::RootMismatch`] for [`bind_anchor_to_package`],
/// [`VerifyError::SignerMismatch`] for [`bind_signer_to_commit`] — plus the
/// length-guard passthrough from [`Package::committed_prefix`]
/// ([`VerifyError::Package`]). It carries NO signature-invalid variant because
/// the PQ signature leg is gated and never runs here (see the module docs);
/// [`SignerMismatch`] is the OFFLINE `pk`↔`signer_commit` wiring mismatch (mock
/// hash, NOT real SHA3-256), not a signature failure.
///
/// [`SignerMismatch`]: VerifyError::SignerMismatch
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The root recomputed from the fetched [`Package`] (through the
    /// [`Hasher`]) does not equal the [`AnchorEnvelope`]'s committed
    /// `manifest_root`. The fetched package is NOT the one this anchor points
    /// at (or one of them was tampered). Carries both roots for diagnostics —
    /// `anchored` is the on-chain claim, `recomputed` is what the bytes hash to.
    RootMismatch {
        /// The `manifest_root` the anchor committed on-chain.
        anchored: [u8; 32],
        /// The root recomputed from the fetched package's committed prefix.
        recomputed: [u8; 32],
    },
    /// The commitment recomputed from the fetched [`Package`]'s `pk` (through
    /// the [`Hasher`] seam — the OFFLINE stand-in for `SHA3-256(pk)`, NOT the
    /// real primitive) does not equal the [`AnchorEnvelope`]'s committed
    /// `signer_commit`. The fetched `pk` is NOT the key this anchor names (or
    /// one was tampered). Carries both values for diagnostics — `anchored` is
    /// the on-chain claim, `recomputed` is what `pk` maps to under the hasher.
    ///
    /// HONESTY: this is a WIRING mismatch under a mock hash, never a signature
    /// failure and never proof of the real signer's identity (that needs a real
    /// `SHA3-256` adapter plus the gated PQ signature leg). See the module docs.
    SignerMismatch {
        /// The `signer_commit` the anchor committed on-chain.
        anchored: [u8; 32],
        /// The commitment recomputed from the fetched package's `pk`.
        recomputed: [u8; 32],
    },
    /// [`Package::committed_prefix`] failed its length guard (a caller-side
    /// invariant violation — a `sealed_manifest` larger than `u32::MAX`), so no
    /// root could be recomputed to compare.
    Package(PackageError),
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RootMismatch { .. } => write!(
                f,
                "data0 verify: manifest_root mismatch — fetched package does not \
                 hash to the anchor's committed root (non-PQ leg only)"
            ),
            Self::SignerMismatch { .. } => write!(
                f,
                "data0 verify: signer_commit mismatch — fetched pk does not map \
                 to the anchor's committed signer_commit (offline wiring leg \
                 only; mock hash, not SHA3-256)"
            ),
            Self::Package(e) => write!(f, "data0 verify: {e}"),
        }
    }
}

impl std::error::Error for VerifyError {}

impl From<PackageError> for VerifyError {
    fn from(e: PackageError) -> Self {
        VerifyError::Package(e)
    }
}

/// Bind a decoded [`AnchorEnvelope`] to a fetched [`Package`] through the
/// [`Hasher`] seam — the **offline, non-PQ** half of §1's verification.
///
/// Recomputes `hasher.manifest_root(package)` (the domain-tagged digest of the
/// package's committed prefix) and asserts it equals `anchor.manifest_root`.
/// Returns `Ok(())` on agreement, [`VerifyError::RootMismatch`] on
/// disagreement, or [`VerifyError::Package`] if the prefix could not be built.
///
/// # This does NOT authenticate anything (gated)
///
/// A passing result binds *these package bytes to this anchor's root* — no
/// more. It does **not** verify the ML-DSA-65‖Falcon-1024 signature and does
/// **not** check `signer_commit == SHA3-256(pk)`; both are gated behind
/// `postern-backup-net` (real crypto). A permissionless anchor over an
/// attacker's own package passes this check. Never treat an `Ok(())` here as
/// evidence a backup is authentic. See the module docs.
pub fn bind_anchor_to_package<H: Hasher>(
    hasher: &H,
    anchor: &AnchorEnvelope,
    package: &Package,
) -> Result<(), VerifyError> {
    let recomputed = hasher.manifest_root(package)?;
    if recomputed == anchor.manifest_root {
        Ok(())
    } else {
        Err(VerifyError::RootMismatch {
            anchored: anchor.manifest_root,
            recomputed,
        })
    }
}

/// Bind a decoded [`AnchorEnvelope`]'s `signer_commit` to a fetched
/// [`Package`]'s `pk` through the [`Hasher`] seam — the **offline, non-PQ**
/// signer-binding leg (§3.2, byte 109).
///
/// Recomputes `hasher.signer_commit(&package.pk)` (the seam's offline stand-in
/// for `SHA3-256(pk)`) and asserts it equals `anchor.signer_commit`. Returns
/// `Ok(())` on agreement or [`VerifyError::SignerMismatch`] on disagreement.
/// Unlike [`bind_anchor_to_package`] it cannot fail on a length guard — `pk` is
/// hashed directly — so it never returns [`VerifyError::Package`].
///
/// # OFFLINE WIRING HALF ONLY — real SHA3-256 + PQ-sig stay gated (LOUD)
///
/// This mirrors the root-binding honesty exactly. A passing result proves the
/// fetched `pk` maps to the anchor's committed `signer_commit` **under the
/// [`Hasher`] passed in** — which, in this crate, is always the
/// ZERO-collision-resistance [`crate::hash::MockHasher`], explicitly **NOT**
/// SHA3-256. It therefore establishes **no authenticity whatsoever**:
///
/// * The **real** `signer_commit == SHA3-256(pk)` preimage check is **gated**
///   — it needs a real `SHA3-256` [`Hasher::signer_commit`] adapter from
///   `postern-backup-net`. Until then this is wiring, not a commitment.
/// * The **PQ signature leg is gated** — even a real SHA3 match only ties `pk`
///   to the anchor; it does not prove `pk` signed anything. A permissionless
///   fee-payer can anchor `(signer_commit, pk)` for a key they control and this
///   check still passes.
///
/// Never treat an `Ok(())` here as evidence of the signer's identity. See the
/// module docs' honesty scope.
pub fn bind_signer_to_commit<H: Hasher>(
    hasher: &H,
    anchor: &AnchorEnvelope,
    package: &Package,
) -> Result<(), VerifyError> {
    let recomputed = hasher.signer_commit(&package.pk);
    if recomputed == anchor.signer_commit {
        Ok(())
    } else {
        Err(VerifyError::SignerMismatch {
            anchored: anchor.signer_commit,
            recomputed,
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::MockHasher;
    use crate::package::{SALT_LEN, TIER_DEFAULT, TIER_FLOOR};

    fn sample_package() -> Package {
        Package {
            kdf_tier: TIER_DEFAULT,
            salt: [0x11; SALT_LEN],
            sealed_manifest: (0u8..=200).collect(),
            pk: vec![0x33; 24],
            sig: vec![0x44; 128],
        }
    }

    /// Build an anchor whose committed `manifest_root` is the honest root of
    /// `package` under `hasher` (the other fields are opaque here).
    fn anchor_for(hasher: &MockHasher, package: &Package) -> AnchorEnvelope {
        AnchorEnvelope {
            namespace_id: [0xAA; 32],
            sequence: 7,
            prev_root: [0xBB; 32],
            manifest_root: hasher.manifest_root(package).unwrap(),
            signer_commit: [0xCC; 32],
            manifest_cid: [0xDD; crate::anchor::CID_LEN],
        }
    }

    #[test]
    fn matching_root_binds_ok() {
        let h = MockHasher::new();
        let p = sample_package();
        let a = anchor_for(&h, &p);
        assert_eq!(bind_anchor_to_package(&h, &a, &p), Ok(()));
    }

    #[test]
    fn one_byte_flip_in_sealed_manifest_is_root_mismatch() {
        let h = MockHasher::new();
        let honest = sample_package();
        let anchor = anchor_for(&h, &honest); // anchor commits to the HONEST root

        // The fetched package is tampered at every single byte position of the
        // sealed manifest; each flip must break the binding.
        for i in 0..honest.sealed_manifest.len() {
            let mut fetched = honest.clone();
            fetched.sealed_manifest[i] ^= 0x01;
            match bind_anchor_to_package(&h, &anchor, &fetched) {
                Err(VerifyError::RootMismatch { anchored, recomputed }) => {
                    assert_eq!(anchored, anchor.manifest_root);
                    assert_ne!(recomputed, anchored, "flip at {i} must move the root");
                }
                other => panic!("expected RootMismatch at byte {i}, got {other:?}"),
            }
        }
    }

    #[test]
    fn flip_in_salt_is_root_mismatch() {
        // committed_prefix covers the salt, so a fetched package with a flipped
        // salt no longer binds to the anchor's root.
        let h = MockHasher::new();
        let honest = sample_package();
        let anchor = anchor_for(&h, &honest);

        let mut fetched = honest.clone();
        fetched.salt[0] ^= 0x01;
        assert!(matches!(
            bind_anchor_to_package(&h, &anchor, &fetched),
            Err(VerifyError::RootMismatch { .. })
        ));
    }

    #[test]
    fn flip_in_kdf_tier_is_root_mismatch() {
        // committed_prefix covers kdf_tier too.
        let h = MockHasher::new();
        let honest = sample_package();
        let anchor = anchor_for(&h, &honest);

        let mut fetched = honest.clone();
        assert_eq!(fetched.kdf_tier, TIER_DEFAULT);
        fetched.kdf_tier = TIER_FLOOR; // the only other valid tier
        assert!(matches!(
            bind_anchor_to_package(&h, &anchor, &fetched),
            Err(VerifyError::RootMismatch { .. })
        ));
    }

    #[test]
    fn flipping_only_pk_or_sig_does_not_break_binding() {
        // The root is over the committed PREFIX, which stops before pk/sig.
        // A verifier who only swapped the trailing pk/sig still sees the same
        // root — the binding is (intentionally) blind to them here. (Whether
        // that pk is the RIGHT signer is the gated signer_commit/PQ leg, which
        // this module does not touch.)
        let h = MockHasher::new();
        let honest = sample_package();
        let anchor = anchor_for(&h, &honest);

        let mut fetched = honest.clone();
        fetched.pk = vec![0xEE; 40]; // different length + bytes
        fetched.sig = vec![0xFF; 200];
        assert_eq!(
            bind_anchor_to_package(&h, &anchor, &fetched),
            Ok(()),
            "pk/sig live outside the committed prefix — binding must still hold"
        );
    }

    #[test]
    fn wrong_anchor_root_is_mismatch_even_for_the_honest_package() {
        // Symmetric to the tamper case: honest package, but the anchor commits
        // to some other root (e.g. an anchor for a different backup set).
        let h = MockHasher::new();
        let p = sample_package();
        let mut anchor = anchor_for(&h, &p);
        anchor.manifest_root[0] ^= 0x01;
        match bind_anchor_to_package(&h, &anchor, &p) {
            Err(VerifyError::RootMismatch { anchored, recomputed }) => {
                assert_eq!(anchored, anchor.manifest_root);
                assert_eq!(recomputed, h.manifest_root(&p).unwrap());
            }
            other => panic!("expected RootMismatch, got {other:?}"),
        }
    }

    #[test]
    fn binding_goes_through_the_hasher_seam() {
        // Sanity: the recomputed root the check compares against is exactly the
        // seam's manifest_root over the committed prefix — no shortcut.
        let h = MockHasher::new();
        let p = sample_package();
        let via_seam = h.manifest_root(&p).unwrap();
        let via_prefix = h.digest(crate::hash::DOMAIN_MANIFEST_ROOT, &p.committed_prefix().unwrap());
        assert_eq!(via_seam, via_prefix);

        let anchor = AnchorEnvelope {
            namespace_id: [0; 32],
            sequence: 0,
            prev_root: [0; 32],
            manifest_root: via_seam,
            signer_commit: [0; 32],
            manifest_cid: [0; crate::anchor::CID_LEN],
        };
        assert_eq!(bind_anchor_to_package(&h, &anchor, &p), Ok(()));
    }

    // ── signer_commit binding (offline wiring half) ──────────────────────────

    /// An anchor whose committed `signer_commit` is the honest seam-commit of
    /// `package.pk` under `hasher` (other fields opaque).
    fn signer_anchor_for(hasher: &MockHasher, package: &Package) -> AnchorEnvelope {
        AnchorEnvelope {
            namespace_id: [0xAA; 32],
            sequence: 7,
            prev_root: [0xBB; 32],
            manifest_root: [0xEE; 32],
            signer_commit: hasher.signer_commit(&package.pk),
            manifest_cid: [0xDD; crate::anchor::CID_LEN],
        }
    }

    #[test]
    fn matching_signer_commit_binds_ok() {
        let h = MockHasher::new();
        let p = sample_package();
        let a = signer_anchor_for(&h, &p);
        assert_eq!(bind_signer_to_commit(&h, &a, &p), Ok(()));
    }

    #[test]
    fn one_byte_flip_in_pk_is_signer_mismatch() {
        // Acceptance: a flipped pk byte yields SignerMismatch through MockHasher.
        let h = MockHasher::new();
        let honest = sample_package();
        let anchor = signer_anchor_for(&h, &honest); // commits to the HONEST pk

        for i in 0..honest.pk.len() {
            let mut fetched = honest.clone();
            fetched.pk[i] ^= 0x01;
            match bind_signer_to_commit(&h, &anchor, &fetched) {
                Err(VerifyError::SignerMismatch { anchored, recomputed }) => {
                    assert_eq!(anchored, anchor.signer_commit);
                    assert_ne!(recomputed, anchored, "pk flip at {i} must move the commit");
                    assert_eq!(recomputed, h.signer_commit(&fetched.pk));
                }
                other => panic!("expected SignerMismatch at pk byte {i}, got {other:?}"),
            }
        }
    }

    #[test]
    fn wrong_committed_signer_value_is_signer_mismatch() {
        // Acceptance: a wrong committed value (honest pk, but the anchor commits
        // to some other signer_commit) yields SignerMismatch.
        let h = MockHasher::new();
        let p = sample_package();
        let mut anchor = signer_anchor_for(&h, &p);
        anchor.signer_commit[0] ^= 0x01; // corrupt the committed value
        match bind_signer_to_commit(&h, &anchor, &p) {
            Err(VerifyError::SignerMismatch { anchored, recomputed }) => {
                assert_eq!(anchored, anchor.signer_commit);
                assert_eq!(recomputed, h.signer_commit(&p.pk));
            }
            other => panic!("expected SignerMismatch, got {other:?}"),
        }
    }

    #[test]
    fn differently_lengthed_pk_is_signer_mismatch() {
        // A fetched pk of a different length (not just a flipped byte) also
        // fails the binding — the seam hashes the whole pk.
        let h = MockHasher::new();
        let honest = sample_package();
        let anchor = signer_anchor_for(&h, &honest);

        let mut fetched = honest.clone();
        fetched.pk = vec![0x33; 40]; // same fill byte, different length
        assert!(matches!(
            bind_signer_to_commit(&h, &anchor, &fetched),
            Err(VerifyError::SignerMismatch { .. })
        ));
    }

    #[test]
    fn signer_binding_goes_through_the_seam() {
        // Sanity: the recomputed value the check compares is exactly the seam's
        // signer_commit over pk — no shortcut.
        let h = MockHasher::new();
        let p = sample_package();
        let via_seam = h.signer_commit(&p.pk);
        let via_domain = h.digest(crate::hash::DOMAIN_SIGNER_COMMIT, &p.pk);
        assert_eq!(via_seam, via_domain);

        let anchor = signer_anchor_for(&h, &p);
        assert_eq!(anchor.signer_commit, via_seam);
        assert_eq!(bind_signer_to_commit(&h, &anchor, &p), Ok(()));
    }

    #[test]
    fn signer_and_root_legs_are_independent() {
        // The two offline legs are orthogonal: flipping pk breaks the signer
        // leg but NOT the root leg (pk is outside committed_prefix); corrupting
        // the anchor's signer_commit breaks the signer leg but NOT the root leg.
        let h = MockHasher::new();
        let honest = sample_package();

        // One anchor that is honest on BOTH legs.
        let anchor = AnchorEnvelope {
            namespace_id: [0xAA; 32],
            sequence: 7,
            prev_root: [0xBB; 32],
            manifest_root: h.manifest_root(&honest).unwrap(),
            signer_commit: h.signer_commit(&honest.pk),
            manifest_cid: [0xDD; crate::anchor::CID_LEN],
        };
        assert_eq!(bind_anchor_to_package(&h, &anchor, &honest), Ok(()));
        assert_eq!(bind_signer_to_commit(&h, &anchor, &honest), Ok(()));

        // Flip a pk byte: signer leg fails, root leg still OK.
        let mut pk_flipped = honest.clone();
        pk_flipped.pk[0] ^= 0x01;
        assert_eq!(bind_anchor_to_package(&h, &anchor, &pk_flipped), Ok(()));
        assert!(matches!(
            bind_signer_to_commit(&h, &anchor, &pk_flipped),
            Err(VerifyError::SignerMismatch { .. })
        ));

        // Flip a sealed_manifest byte: root leg fails, signer leg still OK.
        let mut manifest_flipped = honest.clone();
        manifest_flipped.sealed_manifest[0] ^= 0x01;
        assert!(matches!(
            bind_anchor_to_package(&h, &anchor, &manifest_flipped),
            Err(VerifyError::RootMismatch { .. })
        ));
        assert_eq!(bind_signer_to_commit(&h, &anchor, &manifest_flipped), Ok(()));
    }

    #[test]
    fn signer_mismatch_display_is_honest_about_being_wiring_only() {
        let h = MockHasher::new();
        let p = sample_package();
        let mut anchor = signer_anchor_for(&h, &p);
        anchor.signer_commit[0] ^= 0x01;
        let msg = bind_signer_to_commit(&h, &anchor, &p).unwrap_err().to_string();
        assert!(msg.contains("signer_commit mismatch"), "got: {msg}");
        assert!(msg.contains("not SHA3-256"), "must flag mock hash: {msg}");
    }
}
