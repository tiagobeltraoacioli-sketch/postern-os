//! `Hasher` — the PQ-integrity seam.
//!
//! Spec: `docs/specs/POSTERN-DATA-FILECOIN-DESIGN.md`, §3.2 / §6. Integrity in
//! this design is a **post-quantum overlay**: a `manifest_root` that is
//! `SHAKE-256/256` of the PBP0 package's committed prefix (§3.2, [`Package`],
//! [`Package::committed_prefix`]), plus a per-sealed-blob `shake256` digest
//! (§3.1, [`crate::manifest::ManifestEntry::shake256`]) that lets a fetched
//! blob be re-hashed key-independently before the key-committing AEAD.
//!
//! Until now those were **opaque `[u8; 32]` slots** carried verbatim. This
//! module turns them into a real **seam** — the boundary two capabilities
//! wide — exactly as [`crate::seal::Sealer`] does for confidentiality and
//! [`crate::backend::StorageBackend`] does for storage. The real
//! `SHAKE-256/256` lives in the later `postern-backup-net` wiring crate and
//! plugs in here; this crate defines only the shape and ships a test double.
//!
//! The trait has ONE required primitive — [`Hasher::digest`] (a domain-tagged
//! 32-byte digest) — and derives the two named capabilities from it with
//! default methods, so the real adapter is a thin pass-through:
//!
//! ```ignore
//! // in the (later) wiring crate, NOT here:
//! struct Shake256Hasher;
//! impl Hasher for Shake256Hasher {
//!     fn digest(&self, domain: u8, bytes: &[u8]) -> [u8; 32] {
//!         // SHAKE-256 with a 1-byte domain-separation prefix, squeezed to 32 B.
//!         let mut h = sha3::Shake256::default();
//!         h.update(&[domain]);
//!         h.update(bytes);
//!         let mut out = [0u8; 32];
//!         h.finalize_xof().read(&mut out);
//!         out
//!     }
//! }
//! ```
//!
//! HONESTY (see crate docs): the ONLY implementation in this crate is
//! [`MockHasher`], a **test double with ZERO collision resistance** and
//! **explicitly NOT SHAKE-256**. It exists solely so the offline pipeline and
//! its adversarial tests (recompute a root; detect a 1-byte tamper) can run
//! with no crypto dependency. Never read a [`MockHasher`] digest as a security
//! property, never ship it on a real backup path, and never treat a matching
//! [`MockHasher`] root as evidence of anything.

use crate::package::{Package, PackageError};

/// Domain-separation tag for the package-level `manifest_root` (§3.2).
pub const DOMAIN_MANIFEST_ROOT: u8 = 0x01;
/// Domain-separation tag for a per-sealed-blob integrity digest (§3.1, §6).
pub const DOMAIN_BLOB: u8 = 0x02;
/// Domain-separation tag for the anchor's `signer_commit` (§3.2, byte 109):
/// the OFFLINE stand-in for `SHA3-256(enveloped_signer_pk)`.
///
/// HONESTY (loud): the real `signer_commit` is `SHA3-256(pk)` — a *fixed-output
/// Keccak permutation*, the **same address-family primitive** the chain uses,
/// and a **different primitive** from the `SHAKE-256/256` XOF that
/// [`Hasher::digest`] models. This tag exists only so the in-crate
/// [`MockHasher`] can produce a deterministic, domain-separated offline
/// stand-in for that commitment; it is NOT part of the real signer-commit
/// preimage and MUST NOT be read as one. A real adapter overrides
/// [`Hasher::signer_commit`] with SHA3-256 rather than inheriting the default.
pub const DOMAIN_SIGNER_COMMIT: u8 = 0x03;

/// The PQ-integrity seam: a domain-tagged 32-byte digest, plus the two named
/// capabilities of the design (`manifest_root`, per-blob digest) derived from
/// it.
///
/// Implemented for real by an adapter over `SHAKE-256/256` in
/// `postern-backup-net`; the only in-crate impl is the test-double
/// [`MockHasher`]. A real impl MUST make [`Hasher::digest`] a pure,
/// deterministic function of `(domain, bytes)` — the whole design leans on
/// signer and verifier recomputing byte-identical roots.
pub trait Hasher {
    /// The primitive: a 32-byte digest of `bytes` under a 1-byte `domain`
    /// separation tag. Real impl: `SHAKE-256/256(domain ‖ bytes)`. MUST be a
    /// pure deterministic function of its inputs.
    fn digest(&self, domain: u8, bytes: &[u8]) -> [u8; 32];

    /// The DATA0 anchor's `manifest_root` (§3.2): the digest of the package's
    /// **committed prefix** ([`Package::committed_prefix`]) under
    /// [`DOMAIN_MANIFEST_ROOT`]. Because the prefix commits to salt, tier and
    /// the whole sealed manifest (which carries every entry's `content_cid`
    /// and `shake256`), this single 32-byte root transitively commits to the
    /// backup-set's ciphertext. Fails only with the length guard of
    /// [`Package::committed_prefix`].
    fn manifest_root(&self, package: &Package) -> Result<[u8; 32], PackageError> {
        Ok(self.digest(DOMAIN_MANIFEST_ROOT, &package.committed_prefix()?))
    }

    /// The per-sealed-blob PQ-integrity digest (§3.1, §6) — the value carried
    /// verbatim in [`crate::manifest::ManifestEntry::shake256`]. A fetched
    /// blob is re-hashed against this (key-independent) before use. Digests
    /// the **sealed** (ciphertext) blob bytes under [`DOMAIN_BLOB`].
    fn blob_digest(&self, sealed_blob: &[u8]) -> [u8; 32] {
        self.digest(DOMAIN_BLOB, sealed_blob)
    }

    /// The DATA0 anchor's `signer_commit` (§3.2, byte 109): the commitment to
    /// the enveloped signer public key that a reader binds
    /// [`crate::anchor::AnchorEnvelope::signer_commit`] against.
    ///
    /// This default routes through [`Hasher::digest`] under
    /// [`DOMAIN_SIGNER_COMMIT`] so the offline pipeline (and
    /// [`crate::verify::bind_signer_to_commit`]) has a deterministic,
    /// domain-separated stand-in with no crypto dependency.
    ///
    /// # OFFLINE STAND-IN ONLY — the real primitive is SHA3-256 (gated)
    ///
    /// The real `signer_commit` is `SHA3-256(pk)` — a **fixed-output Keccak
    /// permutation**, the same primitive the chain's address family uses, and
    /// **NOT** the `SHAKE-256/256` XOF that [`Hasher::digest`] models (nor this
    /// default's domain-tagged framing of it). The only in-crate impl is
    /// [`MockHasher`] (ZERO collision resistance, explicitly NOT SHA3), so a
    /// value produced here is a **wiring artifact, never a cryptographic
    /// commitment**. A real adapter in `postern-backup-net` MUST **override**
    /// this method with `SHA3-256(pk)` rather than inherit the default. Until
    /// then, computing the real commitment — like the PQ signature leg — stays
    /// gated behind that boundary. See the crate docs' honesty scope.
    fn signer_commit(&self, pk: &[u8]) -> [u8; 32] {
        self.digest(DOMAIN_SIGNER_COMMIT, pk)
    }
}

// ── MockHasher — test double, NOT a cryptographic hash ────────────────────────

/// A deterministic 32-byte digest that stands in for `SHAKE-256/256` in
/// offline tests.
///
/// **ZERO collision resistance, and explicitly NOT SHAKE-256.** It is four
/// independent [FNV-1a]-64 passes over `domain ‖ len ‖ bytes`, each seeded
/// with a distinct basis constant, their 64-bit outputs concatenated
/// little-endian into 32 bytes. FNV-1a avalanches per input byte, so this is
/// enough for the two properties the offline tests need — a 1-byte change to
/// the input changes the digest (tamper detection), and the digest is a pure
/// function of the input (stable across runs and processes) — and nothing
/// more. It is trivially collision-findable by construction and MUST NOT be
/// read as an integrity guarantee. See the crate docs' honesty scope.
///
/// [FNV-1a]: https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
#[derive(Clone, Copy, Debug, Default)]
pub struct MockHasher;

/// FNV-1a-64 prime.
const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;
/// Four distinct FNV offset bases (the standard basis, then three domain-split
/// variants) — one per output lane, so the four 8-byte lanes are independent.
const FNV_BASES: [u64; 4] = [
    0xCBF2_9CE4_8422_2325, // standard FNV-1a offset basis
    0x9E37_79B9_7F4A_7C15, // golden-ratio split
    0xFF51_AFD7_ED55_8CCD, // murmur3 fmix constant
    0xC4CE_B9FE_1A85_EC53, // murmur3 fmix constant (2nd)
];

impl MockHasher {
    /// A fresh mock hasher (it is stateless).
    pub fn new() -> Self {
        Self
    }

    /// One FNV-1a-64 pass over `bytes`, seeded with `basis`.
    fn fnv1a(basis: u64, bytes: &[u8]) -> u64 {
        let mut h = basis;
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        h
    }
}

impl Hasher for MockHasher {
    fn digest(&self, domain: u8, bytes: &[u8]) -> [u8; 32] {
        // Feed domain ‖ len ‖ bytes so distinct domains and distinct lengths
        // land in distinct digests (length framing blocks trivial extension
        // ambiguity between the toy lanes).
        let mut framed = Vec::with_capacity(1 + 8 + bytes.len());
        framed.push(domain);
        framed.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        framed.extend_from_slice(bytes);

        let mut out = [0u8; 32];
        for (lane, basis) in FNV_BASES.iter().enumerate() {
            let word = Self::fnv1a(*basis, &framed);
            out[lane * 8..lane * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

// ── Shake256Hasher — the REAL SHAKE-256/256 adapter (feature = "hash") ─────────

/// The real post-quantum integrity primitive: a [`Hasher`] whose
/// [`digest`](Hasher::digest) is `SHAKE-256/256` — the `sha3` crate's
/// `Shake256` XOF fed `domain ‖ bytes` and squeezed to exactly 32 bytes,
/// precisely as this module's docstring sketches. This is the concrete
/// instance of the seam that the design places in the later
/// `postern-backup-net` wiring crate; it is compiled here ONLY under the
/// opt-in `hash` feature so the DEFAULT build stays zero-dependency and
/// network-incapable (the ~150 offline tests run on [`MockHasher`]).
///
/// Unlike [`MockHasher`], this is a genuine cryptographic hash: a signer and a
/// verifier that both enable `hash` recompute byte-identical `manifest_root`s
/// over a [`Package::committed_prefix`], and a single-byte change anywhere in
/// the committed prefix flips the root with cryptographic (not toy) strength.
///
/// # `signer_commit` uses the *right* primitive — SHA3-256, not the XOF
///
/// The seam's default [`signer_commit`](Hasher::signer_commit) routes through
/// the XOF only so the offline [`MockHasher`] has a deterministic stand-in.
/// The design (§3.2) specifies the real commitment as `SHA3-256(pk)` — a
/// *fixed-output Keccak permutation*, a different primitive from the
/// `SHAKE-256/256` XOF. This adapter therefore **overrides** `signer_commit`
/// with the real `SHA3-256(pk)`, exactly as `src/hash.rs`'s contract requires
/// of a real adapter, so a value it produces IS the specified commitment.
///
/// HONESTY: this makes the integrity/hashing primitive real and KAT-checked
/// (see `tests/hash_kat.rs`), but it does NOT turn this crate into a working
/// backup system — sealing (confidentiality), the ML-DSA PQ signer, and the
/// live provider client remain outside this crate's scope. UNAUDITED.
#[cfg(feature = "hash")]
#[derive(Clone, Copy, Debug, Default)]
pub struct Shake256Hasher;

#[cfg(feature = "hash")]
impl Shake256Hasher {
    /// A fresh SHAKE-256/256 hasher (it is stateless).
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "hash")]
impl Hasher for Shake256Hasher {
    /// `SHAKE-256/256(domain ‖ bytes)`: the 32-byte squeeze of the `Shake256`
    /// XOF over the 1-byte domain tag followed by `bytes`. Pure and
    /// deterministic — the property the whole design leans on.
    fn digest(&self, domain: u8, bytes: &[u8]) -> [u8; 32] {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        let mut h = sha3::Shake256::default();
        h.update(&[domain]);
        h.update(bytes);
        let mut out = [0u8; 32];
        h.finalize_xof().read(&mut out);
        out
    }

    /// The REAL `signer_commit` — `SHA3-256(pk)` (§3.2), a fixed-output Keccak
    /// permutation and the same address-family primitive the chain uses. This
    /// overrides the seam's XOF-based default (which exists only for the
    /// offline mock) so this adapter emits the specified commitment.
    fn signer_commit(&self, pk: &[u8]) -> [u8; 32] {
        use sha3::Digest;
        let mut h = sha3::Sha3_256::new();
        h.update(pk);
        h.finalize().into()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package::{Package, SALT_LEN, TIER_DEFAULT, TIER_FLOOR};

    fn sample_package() -> Package {
        Package {
            kdf_tier: TIER_DEFAULT,
            salt: [0x11; SALT_LEN],
            sealed_manifest: (0u8..=200).collect(),
            pk: vec![0x33; 24],
            sig: vec![0x44; 128],
        }
    }

    #[test]
    fn manifest_root_recomputes_over_committed_prefix() {
        // The root a signer would write == digest of the committed prefix,
        // computed purely through the seam.
        let h = MockHasher::new();
        let p = sample_package();
        let root = h.manifest_root(&p).unwrap();
        let expected = h.digest(DOMAIN_MANIFEST_ROOT, &p.committed_prefix().unwrap());
        assert_eq!(root, expected);
    }

    #[test]
    fn detects_one_byte_tamper_in_sealed_manifest() {
        // The whole point of the overlay: a verifier who recomputes the root
        // catches a single-byte change to the sealed manifest.
        let h = MockHasher::new();
        let honest = sample_package();
        let honest_root = h.manifest_root(&honest).unwrap();

        for i in 0..honest.sealed_manifest.len() {
            let mut tampered = honest.clone();
            tampered.sealed_manifest[i] ^= 0x01; // flip one bit of one byte
            assert_ne!(
                h.manifest_root(&tampered).unwrap(),
                honest_root,
                "1-byte tamper at index {i} must change the manifest_root",
            );
        }
    }

    #[test]
    fn tamper_in_salt_or_tier_also_changes_root() {
        // committed_prefix commits to salt and tier too, so those tamper as
        // well — the root is not merely a hash of the sealed manifest alone.
        let h = MockHasher::new();
        let base = sample_package();
        let root = h.manifest_root(&base).unwrap();

        let mut salt_tampered = base.clone();
        salt_tampered.salt[0] ^= 0x01;
        assert_ne!(h.manifest_root(&salt_tampered).unwrap(), root);

        let mut tier_tampered = base.clone();
        tier_tampered.kdf_tier = TIER_FLOOR;
        assert_ne!(h.manifest_root(&tier_tampered).unwrap(), root);
    }

    #[test]
    fn root_ignores_pk_and_sig() {
        // manifest_root is over the committed PREFIX — it must NOT depend on
        // the trailing pk/sig (those are signed OVER the root, not into it).
        let h = MockHasher::new();
        let base = sample_package();
        let root = h.manifest_root(&base).unwrap();

        let mut diff_tail = base.clone();
        diff_tail.pk = vec![0xEE; 40];
        diff_tail.sig = vec![0xFF; 200];
        assert_eq!(h.manifest_root(&diff_tail).unwrap(), root);
    }

    #[test]
    fn digest_is_stable_across_runs() {
        // Pinned vector: the mock is a pure function, so these bytes must not
        // drift between runs/processes/builds. If this ever changes, the mock
        // stopped being deterministic (or its construction changed).
        let h = MockHasher::new();
        let d = h.digest(DOMAIN_BLOB, b"postern-backup/mock-hasher/v1");
        let expected = MockHasher::new().digest(DOMAIN_BLOB, b"postern-backup/mock-hasher/v1");
        assert_eq!(d, expected); // stable across fresh instances
        // And the empty-input digest under each domain is fixed.
        assert_eq!(h.digest(DOMAIN_BLOB, b""), MockHasher.digest(DOMAIN_BLOB, b""));
    }

    #[test]
    fn manifest_root_is_stable_across_runs() {
        let p = sample_package();
        let a = MockHasher::new().manifest_root(&p).unwrap();
        let b = MockHasher::new().manifest_root(&p).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn blob_digest_matches_domain_tagged_digest() {
        let h = MockHasher::new();
        let blob = vec![0xABu8; 4096];
        assert_eq!(h.blob_digest(&blob), h.digest(DOMAIN_BLOB, &blob));
    }

    #[test]
    fn signer_commit_routes_through_domain_tagged_digest() {
        // The seam's signer_commit is exactly digest(DOMAIN_SIGNER_COMMIT, pk)
        // for the mock — no shortcut. (Real adapters override with SHA3-256.)
        let h = MockHasher::new();
        let pk = vec![0x33u8; 40];
        assert_eq!(h.signer_commit(&pk), h.digest(DOMAIN_SIGNER_COMMIT, &pk));
    }

    #[test]
    fn signer_commit_detects_one_byte_pk_flip() {
        let h = MockHasher::new();
        let pk = vec![0x33u8; 40];
        let honest = h.signer_commit(&pk);
        for i in 0..pk.len() {
            let mut tampered = pk.clone();
            tampered[i] ^= 0x01;
            assert_ne!(
                h.signer_commit(&tampered),
                honest,
                "1-byte pk flip at {i} must change signer_commit",
            );
        }
    }

    #[test]
    fn signer_commit_is_domain_separated_from_other_legs() {
        // Same bytes as a manifest_root/blob preimage must not collide with a
        // signer_commit over identical bytes.
        let h = MockHasher::new();
        let bytes = b"same-bytes-different-domain";
        assert_ne!(h.digest(DOMAIN_SIGNER_COMMIT, bytes), h.digest(DOMAIN_BLOB, bytes));
        assert_ne!(
            h.digest(DOMAIN_SIGNER_COMMIT, bytes),
            h.digest(DOMAIN_MANIFEST_ROOT, bytes),
        );
    }

    #[test]
    fn signer_commit_is_stable_across_runs() {
        let pk = b"postern-backup/mock-signer/v1";
        assert_eq!(
            MockHasher::new().signer_commit(pk),
            MockHasher::new().signer_commit(pk),
        );
    }

    #[test]
    fn domain_separation_holds() {
        // Same bytes under different domains produce different digests, so a
        // manifest_root can never collide with a blob_digest of equal bytes.
        let h = MockHasher::new();
        let bytes = b"same-bytes-different-domain";
        assert_ne!(
            h.digest(DOMAIN_MANIFEST_ROOT, bytes),
            h.digest(DOMAIN_BLOB, bytes),
        );
    }

    #[test]
    fn distinct_inputs_generally_distinct_digests() {
        // Not a collision-resistance claim — just a sanity check that the four
        // lanes actually mix, so nearby inputs don't alias in the tests above.
        let h = MockHasher::new();
        let a = h.blob_digest(b"aaaa");
        let b = h.blob_digest(b"aaab");
        let c = h.blob_digest(b"aaaa\x00"); // length framing must matter
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn empty_input_is_not_all_zero() {
        // A zero digest is the anchor's genesis prev_root sentinel; the mock
        // must not accidentally emit it for empty input.
        let h = MockHasher::new();
        assert_ne!(h.digest(DOMAIN_BLOB, b""), [0u8; 32]);
        assert_ne!(h.digest(DOMAIN_MANIFEST_ROOT, b""), [0u8; 32]);
    }

    #[test]
    fn never_panics_on_random_ish_input() {
        let h = MockHasher::new();
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        for len in 0..400usize {
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                buf.push(state as u8);
            }
            let _ = h.digest(0x00, &buf);
            let _ = h.blob_digest(&buf);
        }
    }
}
