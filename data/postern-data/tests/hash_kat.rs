//! Known-Answer Tests for the real `SHAKE-256/256` integrity primitive
//! (`hash::Shake256Hasher`), compiled ONLY under the opt-in `hash` feature.
//!
//! Run: `cargo test --offline --features hash`.
//!
//! Why this file exists: the default build carries only [`MockHasher`], a test
//! double with ZERO collision resistance that is explicitly NOT SHAKE-256.
//! These tests are the evidence that the feature-gated
//! [`bloch_data::Shake256Hasher`] is the *real* primitive:
//!
//!  1. its `digest` matches **published SHAKE-256/256 KAT vectors** — the
//!     canonical empty-message vector plus cross-implementation vectors
//!     computed independently with Python's `hashlib.shake_256` (a different
//!     codebase from RustCrypto's `sha3`), so a match pins the byte-exact
//!     output, not just self-consistency;
//!  2. a **1-byte change to the input flips the `manifest_root`** — the tamper
//!     property the whole PQ-integrity overlay leans on; and
//!  3. its overridden `signer_commit` is the real **SHA3-256(pk)** (§3.2), a
//!     fixed-output Keccak permutation distinct from the XOF, checked against
//!     the published SHA3-256 KAT.
//!
//! HONESTY: passing these proves the *hashing primitive* is real and
//! byte-correct. It does NOT make the crate a working backup system — sealing,
//! the ML-DSA PQ signer, and the live provider client remain out of scope.
//! UNAUDITED.
#![cfg(feature = "hash")]

use bloch_data::hash::{DOMAIN_BLOB, DOMAIN_MANIFEST_ROOT, DOMAIN_SIGNER_COMMIT};
use bloch_data::package::{SALT_LEN, TIER_DEFAULT, TIER_FLOOR};
use bloch_data::{Hasher, Package, Shake256Hasher};

/// Parse a 64-char lowercase-hex string into a fixed 32-byte KAT expectation.
fn h32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "a 32-byte digest is 64 hex chars");
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("valid hex");
    }
    out
}

/// The canonical, widely published `SHAKE-256` vector: the empty message
/// squeezed to 256 bits. Pins the underlying XOF to the *standard* SHAKE-256,
/// computed here through the raw `sha3::Shake256` the adapter uses.
#[test]
fn raw_shake256_empty_matches_published_kat() {
    use sha3::digest::{ExtendableOutput, XofReader};
    let mut out = [0u8; 32];
    sha3::Shake256::default().finalize_xof().read(&mut out);
    assert_eq!(
        out,
        h32("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"),
        "sha3::Shake256 must reproduce the canonical SHAKE-256/256 empty-message KAT",
    );
}

/// The adapter's `digest(domain, bytes)` == `SHAKE-256/256(domain ‖ bytes)`,
/// pinned to vectors computed INDEPENDENTLY with Python's `hashlib.shake_256`.
/// A match across two unrelated implementations is the KAT: it proves the
/// domain-tagged framing squeezes to exactly the standard SHAKE-256 output.
#[test]
fn digest_matches_independent_shake256_kat_vectors() {
    let h = Shake256Hasher::new();

    // (domain, message, expected SHAKE-256(domain ‖ message) as 32-byte hex)
    let vectors: &[(u8, &[u8], &str)] = &[
        (
            DOMAIN_MANIFEST_ROOT,
            b"",
            "94da6280b240ea6a2ab2cfdf0fb301fd77153d5b748baf796190856803d977ba",
        ),
        (
            DOMAIN_BLOB,
            b"",
            "8973698ae20544521cd22cb31e86e3339a9b5b7d7cb4adb2ca59716b5eacf851",
        ),
        (
            DOMAIN_BLOB,
            b"abc",
            "dfdf1205a37646f1ea28094831fb63a1e4de459d1ebe0fb9cbb7600c0c625491",
        ),
        (
            DOMAIN_MANIFEST_ROOT,
            b"postern-data/kat/v1",
            "dffe5fbaa697bb664b34f5839b08823657f69ee7d0dca81d0a7e7ce63d77d552",
        ),
    ];

    for (domain, msg, expected) in vectors {
        assert_eq!(
            h.digest(*domain, msg),
            h32(expected),
            "SHAKE-256/256 KAT mismatch for domain {domain:#04x}, msg {msg:?}",
        );
    }
}

/// The two named capabilities are literally the domain-tagged XOF, so they
/// inherit the KAT: `blob_digest(b"abc") == digest(DOMAIN_BLOB, b"abc")`.
#[test]
fn blob_digest_inherits_the_kat() {
    let h = Shake256Hasher::new();
    assert_eq!(
        h.blob_digest(b"abc"),
        h32("dfdf1205a37646f1ea28094831fb63a1e4de459d1ebe0fb9cbb7600c0c625491"),
    );
}

fn sample_package() -> Package {
    Package {
        kdf_tier: TIER_DEFAULT,
        salt: [0x11; SALT_LEN],
        sealed_manifest: (0u8..=200).collect(),
        pk: vec![0x33; 24],
        sig: vec![0x44; 128],
    }
}

/// The acceptance property: a 1-byte change ANYWHERE in the committed prefix
/// (here: each byte of the sealed manifest) flips the real `manifest_root`.
#[test]
fn one_byte_change_flips_manifest_root() {
    let h = Shake256Hasher::new();
    let honest = sample_package();
    let honest_root = h.manifest_root(&honest).unwrap();

    for i in 0..honest.sealed_manifest.len() {
        let mut tampered = honest.clone();
        tampered.sealed_manifest[i] ^= 0x01; // flip one bit of one byte
        assert_ne!(
            h.manifest_root(&tampered).unwrap(),
            honest_root,
            "1-byte tamper at sealed_manifest[{i}] must change the manifest_root",
        );
    }

    // The prefix also commits to salt and KDF tier, so those flip it too.
    let mut salt_tampered = honest.clone();
    salt_tampered.salt[0] ^= 0x01;
    assert_ne!(h.manifest_root(&salt_tampered).unwrap(), honest_root);

    let mut tier_tampered = honest.clone();
    tier_tampered.kdf_tier = TIER_FLOOR;
    assert_ne!(h.manifest_root(&tier_tampered).unwrap(), honest_root);
}

/// `manifest_root` is over the committed PREFIX, so it is byte-identical for
/// two signers that both run the real hasher — the recompute the design needs.
#[test]
fn manifest_root_recomputes_deterministically() {
    let p = sample_package();
    let a = Shake256Hasher::new().manifest_root(&p).unwrap();
    let b = Shake256Hasher::new().manifest_root(&p).unwrap();
    assert_eq!(a, b);
    // And it is exactly the domain-tagged digest of the committed prefix.
    let expected =
        Shake256Hasher::new().digest(DOMAIN_MANIFEST_ROOT, &p.committed_prefix().unwrap());
    assert_eq!(a, expected);
    // The trailing pk/sig are NOT in the prefix, so they don't move the root.
    let mut diff_tail = p.clone();
    diff_tail.pk = vec![0xEE; 40];
    diff_tail.sig = vec![0xFF; 200];
    assert_eq!(Shake256Hasher::new().manifest_root(&diff_tail).unwrap(), a);
}

/// The adapter OVERRIDES `signer_commit` with the real `SHA3-256(pk)` (§3.2) —
/// a fixed-output Keccak, NOT the XOF. Pinned to the published SHA3-256 empty
/// KAT and to an independently computed SHA3-256 of a sample key.
#[test]
fn signer_commit_is_real_sha3_256_not_the_xof() {
    let h = Shake256Hasher::new();

    // Published NIST SHA3-256("") KAT.
    assert_eq!(
        h.signer_commit(b""),
        h32("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
        "signer_commit(b\"\") must be the published SHA3-256 empty KAT",
    );

    // Independently computed SHA3-256(0x33 * 40).
    let pk = vec![0x33u8; 40];
    assert_eq!(
        h.signer_commit(&pk),
        h32("106319ea446bc9716e1a360d9d5577d1fee31cf19a55b0c6aeb3d278e452fdd6"),
    );

    // It must NOT be the XOF-framed default (that is the mock's stand-in): the
    // real SHA3-256(pk) is a different primitive from SHAKE-256(0x03 ‖ pk).
    assert_ne!(
        h.signer_commit(&pk),
        h.digest(DOMAIN_SIGNER_COMMIT, &pk),
        "the real adapter's signer_commit must differ from the XOF default",
    );

    // Tamper property still holds on the commit.
    for i in 0..pk.len() {
        let mut t = pk.clone();
        t[i] ^= 0x01;
        assert_ne!(h.signer_commit(&t), h.signer_commit(&pk));
    }
}

/// Domain separation under the real XOF: identical bytes under different domain
/// tags give different digests, so a `manifest_root` can never alias a
/// `blob_digest` of equal bytes.
#[test]
fn real_digest_is_domain_separated() {
    let h = Shake256Hasher::new();
    let bytes = b"same-bytes-different-domain";
    assert_ne!(
        h.digest(DOMAIN_MANIFEST_ROOT, bytes),
        h.digest(DOMAIN_BLOB, bytes),
    );
    assert_ne!(
        h.digest(DOMAIN_MANIFEST_ROOT, bytes),
        h.digest(DOMAIN_SIGNER_COMMIT, bytes),
    );
    // A real SHAKE-256 digest of a non-empty input is not the zero sentinel.
    assert_ne!(h.digest(DOMAIN_BLOB, b""), [0u8; 32]);
}
