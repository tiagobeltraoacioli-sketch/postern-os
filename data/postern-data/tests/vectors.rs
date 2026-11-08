//! Golden byte-for-byte wire vectors + an offline end-to-end pipeline smoke
//! test, pinned to `docs/specs/POSTERN-DATA-FILECOIN-DESIGN.md` §2 (DATA0),
//! §3.1 (PBM0) and §3.2 (PBP0). Mirrors `l2/bloch-l2-anchor/tests/vectors.rs`.
//!
//! Every golden vector below is HAND-WRITTEN HEX transcribed from the spec
//! byte tables — never produced by calling `encode()` (which would make the
//! test tautological). If the spec layout and the code ever disagree, these
//! tests fail.

use bloch_data::anchor::{
    decode_anchor_output, link, select_head, AnchorEnvelope, EnvelopeError, TxOut, CID_LEN,
    ENVELOPE_LEN, ENVELOPE_MAGIC, ENVELOPE_VERSION,
};
use bloch_data::backend::{MockBackend, StorageBackend};
use bloch_data::manifest::{Manifest, ManifestEntry, ManifestError};
use bloch_data::package::{Package, PackageError, TIER_DEFAULT};
use bloch_data::seal::{MockSealer, Opener, SealError, Sealer};

// Additional surface exercised only by the journal evidence-chain integration
// test at the bottom of this file (kept separate so the golden-vector imports
// above stay untouched).
use bloch_data::anchor::{extract_anchor, Tx, TxIn};
use bloch_data::backend::{Cid, DealInfo, DealStatus};
use bloch_data::hash::{Hasher, MockHasher, DOMAIN_BLOB};
use bloch_data::journal::{
    AnchorDepth, Evidence, Journal, JournalError, Stage, ANCHOR_CAVEAT, FORBIDDEN_CLAIMS,
};

/// Whitespace-tolerant hex → bytes. Test-only helper; the hex literals
/// themselves are the source of truth.
fn hex(s: &str) -> Vec<u8> {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(compact.len() % 2 == 0, "odd-length hex literal");
    (0..compact.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&compact[i..i + 2], 16).expect("bad hex literal"))
        .collect()
}

/// The `00 01 … 1F` 32-byte pattern shared by the golden vectors.
fn pattern_32() -> [u8; 32] {
    let mut id = [0u8; 32];
    for (i, b) in id.iter_mut().enumerate() {
        *b = i as u8;
    }
    id
}

// ── Golden DATA0 anchor vector (fixed 177 bytes) ──────────────────────────────
//
//   magic "DAT0"            44 41 54 30
//   version                 00
//   namespace_id 00..1F     00 01 ... 1F                     (32 bytes)
//   sequence 7  u64-LE      07 00 00 00 00 00 00 00
//   prev_root      AA*32    AA ... AA                         (32 bytes)
//   manifest_root  BB*32    BB ... BB                         (32 bytes)
//   signer_commit  CC*32    CC ... CC                         (32 bytes)
//   manifest_cid   DD*36    DD ... DD                         (36 bytes)
const GOLDEN_ANCHOR_HEX: &str = "44415430 00 \
     000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F \
     0700000000000000 \
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \
     BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB \
     CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC \
     DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";

fn golden_anchor() -> AnchorEnvelope {
    AnchorEnvelope {
        namespace_id: pattern_32(),
        sequence: 7,
        prev_root: [0xAA; 32],
        manifest_root: [0xBB; 32],
        signer_commit: [0xCC; 32],
        manifest_cid: [0xDD; CID_LEN],
    }
}

#[test]
fn anchor_vector_matches_spec_offsets() {
    let v = hex(GOLDEN_ANCHOR_HEX);
    assert_eq!(v.len(), 177);
    assert_eq!(v.len(), ENVELOPE_LEN, "code constant must equal spec length");
    assert_eq!(&v[0..4], b"DAT0", "magic at offset 0");
    assert_eq!(&v[0..4], &ENVELOPE_MAGIC);
    assert_eq!(&v[0..4], &[0x44, 0x41, 0x54, 0x30], "magic bytes 44 41 54 30");
    assert_eq!(v[4], 0x00, "version at offset 4");
    assert_eq!(v[4], ENVELOPE_VERSION);
    assert_eq!(&v[5..37], &pattern_32()[..], "namespace_id at offset 5");
    assert_eq!(
        u64::from_le_bytes(v[37..45].try_into().unwrap()),
        7,
        "sequence u64-LE at offset 37"
    );
    assert_eq!(&v[45..77], &[0xAA; 32], "prev_root at offset 45");
    assert_eq!(&v[77..109], &[0xBB; 32], "manifest_root at offset 77");
    assert_eq!(&v[109..141], &[0xCC; 32], "signer_commit at offset 109");
    assert_eq!(&v[141..177], &[0xDD; CID_LEN], "manifest_cid at offset 141");
}

#[test]
fn anchor_vector_decodes_and_re_encodes() {
    let decoded = AnchorEnvelope::decode(&hex(GOLDEN_ANCHOR_HEX)).expect("golden must decode");
    assert_eq!(decoded, golden_anchor());
    assert_eq!(golden_anchor().encode(), hex(GOLDEN_ANCHOR_HEX), "encode diverged from spec");
}

#[test]
fn anchor_signing_transcript_excludes_manifest_cid() {
    // Transcript = domain ‖ envelope[..141] (everything the signature covers);
    // the 36-byte manifest_cid locator is unsigned by design (§3.2).
    let v = hex(GOLDEN_ANCHOR_HEX);
    let t = golden_anchor().signing_transcript();
    assert_eq!(&t[0..24], b"postern-backup/anchor/v0");
    assert_eq!(&t[24..], &v[0..141], "transcript is domain ‖ envelope minus the CID");
    assert_eq!(t.len(), 24 + 141);
}

#[test]
fn anchor_reject_vectors_are_typed() {
    let cases: &[(&str, &str, EnvelopeError)] = &[
        ("empty", "", EnvelopeError::Truncated),
        ("short of magic", "444154", EnvelopeError::Truncated),
        ("bad magic (L2V0)", "4C325630 00", EnvelopeError::BadMagic),
        ("bad version 0x01", "44415430 01", EnvelopeError::BadVersion(0x01)),
        ("header only", "44415430 00", EnvelopeError::Truncated),
    ];
    for (name, hx, expected) in cases {
        assert_eq!(AnchorEnvelope::decode(&hex(hx)), Err(expected.clone()), "reject {name:?}");
    }
}

#[test]
fn anchor_rejects_nonzero_value_output() {
    let out = TxOut { value: 5_000, script_pubkey: hex(GOLDEN_ANCHOR_HEX) };
    assert_eq!(decode_anchor_output(&out), Err(EnvelopeError::NonZeroValue(5_000)));
}

#[test]
fn golden_anchor_links_to_hand_built_successor() {
    // Successor: sequence 8, prev_root = golden manifest_root (BB*32).
    let successor_hex = "44415430 00 \
         000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F \
         0800000000000000 \
         BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB \
         EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE \
         CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC \
         DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";
    let prev = AnchorEnvelope::decode(&hex(GOLDEN_ANCHOR_HEX)).unwrap();
    let next = AnchorEnvelope::decode(&hex(successor_hex)).unwrap();
    assert_eq!(link(&prev, &next), Ok(()));
}

// ── Adversarial head selection (select_head) ──────────────────────────────────
//
// A pure reader-side fork-choice for ONE vault: from an unordered, adversarial
// bag of anchors (any order, replays, gaps, competing forks, foreign vaults),
// return the tip of the longest link-valid chain rooted at that vault's genesis.
// Field mapping: vault_id = namespace_id, manifest_index = sequence, new_root =
// manifest_root, and each `prev_root -> new_root` step is exactly `link`.
//
// Table-driven, per the acceptance: genesis, a clean chain, a gap (missing
// index) rejected, a replayed index rejected, and two competing forks resolving
// deterministically to the higher-sequence valid head — plus the vault filter.

const VAULT: [u8; 32] = [0x11; 32];
const OTHER_VAULT: [u8; 32] = [0x22; 32];
const GENESIS_PREV: [u8; 32] = [0u8; 32];

/// Anchor carrying only the fields head-selection reads (vault, sequence,
/// prev_root, manifest_root); signer_commit / manifest_cid are fixed filler.
fn sel_node(ns: [u8; 32], sequence: u64, prev_root: [u8; 32], manifest_root: [u8; 32]) -> AnchorEnvelope {
    AnchorEnvelope {
        namespace_id: ns,
        sequence,
        prev_root,
        manifest_root,
        signer_commit: [0xCC; 32],
        manifest_cid: [0xDD; CID_LEN],
    }
}

/// A 32-byte root filled with `n` — distinct roots make each chain link forgery-
/// resistant in the fixtures (a wrong prev_root cannot accidentally match).
fn sel_root(n: u8) -> [u8; 32] {
    [n; 32]
}

#[test]
fn select_head_table() {
    // Each case: a human label, the adversarial anchor bag, the vault under
    // test, and the expected head (`None` = the vault has no valid chain).
    struct Case {
        label: &'static str,
        anchors: Vec<AnchorEnvelope>,
        vault: [u8; 32],
        expected: Option<AnchorEnvelope>,
    }

    // Shared chain roots: r(k) is the manifest_root committed at sequence k, so
    // the canonical link at k+1 has prev_root == r(k).
    let (r0, r1, r2, r3) = (sel_root(0xA0), sel_root(0xA1), sel_root(0xA2), sel_root(0xA3));

    // Canonical chain nodes for VAULT (genesis .. seq 3).
    let g = sel_node(VAULT, 0, GENESIS_PREV, r0);
    let n1 = sel_node(VAULT, 1, r0, r1);
    let n2 = sel_node(VAULT, 2, r1, r2);
    let n3 = sel_node(VAULT, 3, r2, r3);

    let cases = vec![
        // ── genesis (prev_root all-zero) ─────────────────────────────────
        Case {
            label: "genesis only (prev_root all-zero) is its own head",
            anchors: vec![g.clone()],
            vault: VAULT,
            expected: Some(g.clone()),
        },
        // ── clean chain (with a foreign-vault anchor that must be ignored) ─
        Case {
            label: "clean chain 0->1->2->3, unordered, foreign vault ignored",
            anchors: vec![
                n2.clone(),
                sel_node(OTHER_VAULT, 9, GENESIS_PREV, sel_root(0xF0)), // higher seq, other vault
                g.clone(),
                n3.clone(),
                n1.clone(),
            ],
            vault: VAULT,
            expected: Some(n3.clone()),
        },
        // ── gap (missing index 2) rejected: head stays at the tip before it ─
        Case {
            label: "gap at index 2 severs the chain; head is seq 1",
            anchors: vec![
                g.clone(),
                n1.clone(),
                // seq 3 present but seq 2 missing: n3 links to a non-existent
                // seq-2 predecessor, so it is unreachable and NOT the head.
                n3.clone(),
            ],
            vault: VAULT,
            expected: Some(n1.clone()),
        },
        // ── replayed index rejected: a duplicate seq 1 with a different root ─
        Case {
            label: "replayed seq 1 (different root) loses to the real linked chain",
            anchors: vec![
                g.clone(),
                n1.clone(),
                // Replay of index 1: same sequence, different manifest_root,
                // does NOT link to seq 2 (whose prev_root == r1, the real n1).
                sel_node(VAULT, 1, r0, sel_root(0xEE)),
                n2.clone(),
            ],
            vault: VAULT,
            expected: Some(n2.clone()),
        },
        // ── two competing forks resolve to the higher-sequence valid head ──
        Case {
            label: "fork at seq 2; the longer branch (to seq 3) wins deterministically",
            anchors: vec![
                g.clone(),
                n1.clone(),
                n2.clone(),                                   // fork A tip-1: root r2
                sel_node(VAULT, 2, r1, sel_root(0xB2)),       // fork B tip: root r2b, no successor
                n3.clone(),                                   // extends fork A (prev_root == r2)
            ],
            vault: VAULT,
            expected: Some(n3.clone()),
        },
        // ── the vault filter is total: no anchors for the queried vault ────
        Case {
            label: "only foreign-vault anchors => no head for VAULT",
            anchors: vec![
                sel_node(OTHER_VAULT, 0, GENESIS_PREV, sel_root(0xF0)),
                sel_node(OTHER_VAULT, 1, sel_root(0xF0), sel_root(0xF1)),
            ],
            vault: VAULT,
            expected: None,
        },
    ];

    for case in &cases {
        let got = select_head(&case.anchors, &case.vault);
        assert_eq!(got, case.expected.as_ref(), "case: {}", case.label);
        // Cross-check: a returned head must actually be link-reachable — its
        // whole chain back to genesis must exist in the bag (a real head is
        // never a floating claim).
        if let Some(head) = got {
            assert!(chain_reaches_genesis(&case.anchors, &case.vault, head), "case: {}", case.label);
        }
    }
}

/// Walk `head` back to genesis using `link`, confirming every predecessor is
/// present in `anchors` and belongs to `vault`. Independent of `select_head`'s
/// internals: it re-derives reachability through the public `link` predicate.
fn chain_reaches_genesis(anchors: &[AnchorEnvelope], vault: &[u8; 32], head: &AnchorEnvelope) -> bool {
    let mut cur = head.clone();
    loop {
        if &cur.namespace_id != vault {
            return false;
        }
        if cur.sequence == 0 {
            return cur.prev_root == [0u8; 32];
        }
        let pred = anchors.iter().find(|p| {
            &p.namespace_id == vault && p.sequence == cur.sequence - 1 && link(p, &cur).is_ok()
        });
        match pred {
            Some(p) => cur = p.clone(),
            None => return false,
        }
    }
}

// ── Golden PBM0 manifest vector ───────────────────────────────────────────────
//
//   magic "PBM0"            50 42 4D 30
//   version                 00
//   backup_set_id 00..1F    00 01 ... 1F                     (32 bytes)
//   sequence 7   u64-LE     07 00 00 00 00 00 00 00
//   created_unix 99 u64-LE  63 00 00 00 00 00 00 00
//   entry_count 1 u32-LE    01 00 00 00
//   entry[0]:
//     path_len 2   u16-LE   02 00
//     path "ab"             61 62
//     file_len 73  u64-LE   49 00 00 00 00 00 00 00
//     content_cid_len 4 u8  04
//     content_cid           DE AD BE EF
//     shake256 33*32        33 ... 33                         (32 bytes)
const GOLDEN_MANIFEST_HEX: &str = "50424D30 00 \
     000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F \
     0700000000000000 \
     6300000000000000 \
     01000000 \
     0200 6162 4900000000000000 04 DEADBEEF \
     3333333333333333333333333333333333333333333333333333333333333333";

fn golden_manifest() -> Manifest {
    Manifest {
        backup_set_id: pattern_32(),
        sequence: 7,
        created_unix: 99,
        entries: vec![ManifestEntry {
            path: b"ab".to_vec(),
            file_len: 73,
            content_cid: vec![0xDE, 0xAD, 0xBE, 0xEF],
            shake256: [0x33; 32],
        }],
    }
}

#[test]
fn manifest_vector_matches_spec_offsets() {
    let v = hex(GOLDEN_MANIFEST_HEX);
    assert_eq!(&v[0..4], b"PBM0");
    assert_eq!(v[4], 0x00);
    assert_eq!(&v[5..37], &pattern_32()[..]); // backup_set_id
    assert_eq!(u64::from_le_bytes(v[37..45].try_into().unwrap()), 7); // sequence
    assert_eq!(u64::from_le_bytes(v[45..53].try_into().unwrap()), 99); // created_unix
    assert_eq!(u32::from_le_bytes(v[53..57].try_into().unwrap()), 1); // entry_count
    assert_eq!(u16::from_le_bytes(v[57..59].try_into().unwrap()), 2); // path_len
    assert_eq!(&v[59..61], b"ab"); // path
    assert_eq!(u64::from_le_bytes(v[61..69].try_into().unwrap()), 73); // file_len
    assert_eq!(v[69], 0x04); // content_cid_len
    assert_eq!(&v[70..74], &[0xDE, 0xAD, 0xBE, 0xEF]); // content_cid
    assert_eq!(&v[74..106], &[0x33; 32]); // shake256
    assert_eq!(v.len(), 106);
}

#[test]
fn manifest_vector_decodes_and_re_encodes() {
    let bytes = hex(GOLDEN_MANIFEST_HEX);
    let decoded = Manifest::decode(&bytes).expect("golden manifest must decode");
    assert_eq!(decoded, golden_manifest());
    assert_eq!(golden_manifest().encode().unwrap(), bytes, "encode diverged from spec");
}

#[test]
fn manifest_reject_vectors_are_typed() {
    assert_eq!(Manifest::decode(&hex("44415430 00")), Err(ManifestError::BadMagic));
    let mut trailing = hex(GOLDEN_MANIFEST_HEX);
    trailing.push(0xFF);
    assert_eq!(Manifest::decode(&trailing), Err(ManifestError::TrailingBytes));
    let full = hex(GOLDEN_MANIFEST_HEX);
    for cut in 0..full.len() {
        let err = Manifest::decode(&full[..cut]).expect_err("prefix must fail");
        assert!(matches!(err, ManifestError::Truncated | ManifestError::BadMagic));
    }
}

// ── Golden PBP0 package vector ────────────────────────────────────────────────
//
//   magic "PBP0"            50 42 50 30
//   version                 00
//   kdf_tier default        00
//   salt 11*16              11 ... 11                         (16 bytes)
//   sealed_manifest_len 4   04 00 00 00
//   sealed_manifest         DE AD BE EF
//   pk_len 2                02 00 00 00
//   pk                      33 44
//   sig_len 3               03 00 00 00
//   sig                     01 02 03
const GOLDEN_PACKAGE_HEX: &str = "50425030 00 00 \
     11111111111111111111111111111111 \
     04000000 DEADBEEF \
     02000000 3344 \
     03000000 010203";

fn golden_package() -> Package {
    Package {
        kdf_tier: TIER_DEFAULT,
        salt: [0x11; 16],
        sealed_manifest: vec![0xDE, 0xAD, 0xBE, 0xEF],
        pk: vec![0x33, 0x44],
        sig: vec![0x01, 0x02, 0x03],
    }
}

#[test]
fn package_vector_matches_spec_offsets() {
    let v = hex(GOLDEN_PACKAGE_HEX);
    assert_eq!(&v[0..4], b"PBP0");
    assert_eq!(v[4], 0x00); // version
    assert_eq!(v[5], 0x00); // kdf_tier default
    assert_eq!(&v[6..22], &[0x11; 16]); // salt
    assert_eq!(u32::from_le_bytes(v[22..26].try_into().unwrap()), 4); // sealed_manifest_len
    assert_eq!(&v[26..30], &[0xDE, 0xAD, 0xBE, 0xEF]); // sealed_manifest
    assert_eq!(u32::from_le_bytes(v[30..34].try_into().unwrap()), 2); // pk_len
    assert_eq!(&v[34..36], &[0x33, 0x44]); // pk
    assert_eq!(u32::from_le_bytes(v[36..40].try_into().unwrap()), 3); // sig_len
    assert_eq!(&v[40..43], &[0x01, 0x02, 0x03]); // sig
    assert_eq!(v.len(), 43);
    // committed_prefix stops right after sealed_manifest (offset 30).
    assert_eq!(golden_package().committed_prefix().unwrap(), &v[0..30]);
}

#[test]
fn package_vector_decodes_and_re_encodes() {
    let bytes = hex(GOLDEN_PACKAGE_HEX);
    let decoded = Package::decode(&bytes).expect("golden package must decode");
    assert_eq!(decoded, golden_package());
    assert_eq!(golden_package().encode().unwrap(), bytes, "encode diverged from spec");
}

#[test]
fn package_reject_vectors_are_typed() {
    // unknown kdf_tier 0x02
    let mut bad_tier = hex(GOLDEN_PACKAGE_HEX);
    bad_tier[5] = 0x02;
    assert_eq!(Package::decode(&bad_tier), Err(PackageError::BadTier(0x02)));
    // trailing byte
    let mut trailing = hex(GOLDEN_PACKAGE_HEX);
    trailing.push(0x00);
    assert_eq!(Package::decode(&trailing), Err(PackageError::TrailingBytes));
}

// ── Offline end-to-end pipeline smoke test (no network, no real crypto) ───────
//
// Exercises the whole offline seam: build a PBM0 manifest → seal it
// (MockSealer) → wrap in a PBP0 package → upload to a MockBackend → fetch it
// back → decode the package → open the sealed manifest → decode → compare.
// Then the adversarial negatives the live path must survive: provider
// substitutes bytes, wrong key, wrong context.

fn sample_manifest() -> Manifest {
    Manifest {
        backup_set_id: [0x11; 32],
        sequence: 3,
        created_unix: 1_700_000_000,
        entries: vec![
            ManifestEntry {
                path: b"a.txt".to_vec(),
                file_len: 4096,
                content_cid: b"cid-a".to_vec(),
                shake256: [0xA0; 32],
            },
            ManifestEntry {
                path: b"b.txt".to_vec(),
                file_len: 12,
                content_cid: b"cid-b".to_vec(),
                shake256: [0xB0; 32],
            },
        ],
    }
}

#[test]
fn offline_pipeline_round_trip() {
    let ctx: &[u8] = b"postern-backup/manifest/v1";
    let sealer = MockSealer::new([0x42; 32]);
    let mut backend = MockBackend::new();

    // Build + encode the plaintext PBM0 manifest (lives only inside the seal).
    let manifest = sample_manifest();
    let manifest_bytes = manifest.encode().unwrap();

    // Seal it, wrap in a PBP0 package (pk/sig are opaque slots this crate never
    // computes), upload the package as an opaque CAR.
    let sealed = sealer.seal(ctx, &manifest_bytes).unwrap();
    let package = Package {
        kdf_tier: TIER_DEFAULT,
        salt: [0x7E; 16],
        sealed_manifest: sealed,
        pk: vec![0x01; 8],  // slot, filled by the out-of-scope signer
        sig: vec![0x02; 16], // slot, filled by the out-of-scope signer
    };
    let package_bytes = package.encode().unwrap();
    let cid = backend.put_car(&package_bytes).unwrap();

    // Recover: fetch → decode package → open sealed manifest → decode.
    let fetched = backend.get(&cid).unwrap();
    let decoded_pkg = Package::decode(&fetched).unwrap();
    assert_eq!(decoded_pkg, package);
    let opened = sealer.open(ctx, &decoded_pkg.sealed_manifest).unwrap();
    assert_eq!(Manifest::decode(&opened).unwrap(), manifest);

    // The committed prefix is a genuine prefix of the uploaded package bytes —
    // manifest_root = SHAKE-256(prefix) (the hash itself is out of scope).
    let prefix = decoded_pkg.committed_prefix().unwrap();
    assert_eq!(&package_bytes[..prefix.len()], &prefix[..]);
}

#[test]
fn offline_pipeline_detects_provider_substitution() {
    // The seam's whole point: backend bytes are untrusted. If the provider
    // swaps the ciphertext, the key-committing open (here the MockSealer's toy
    // check) rejects it rather than returning attacker-chosen plaintext.
    let ctx: &[u8] = b"postern-backup/manifest/v1";
    let sealer = MockSealer::new([0x42; 32]);
    let mut backend = MockBackend::new();

    let sealed = sealer.seal(ctx, b"honest manifest bytes").unwrap();
    let cid = backend.put_car(&sealed).unwrap();
    backend.corrupt(&cid, b"attacker-substituted junk".to_vec());

    let fetched = backend.get(&cid).unwrap();
    assert_eq!(sealer.open(ctx, &fetched), Err(SealError::Corrupt));
}

#[test]
fn offline_pipeline_wrong_key_and_context_fail() {
    let ctx: &[u8] = b"postern-backup/manifest/v1";
    let sealer = MockSealer::new([0x42; 32]);
    let mut backend = MockBackend::new();

    let sealed = sealer.seal(ctx, b"secret manifest").unwrap();
    let cid = backend.put_car(&sealed).unwrap();
    let fetched = backend.get(&cid).unwrap();

    // Wrong context.
    assert_eq!(sealer.open(b"wrong/context", &fetched), Err(SealError::Open));
    // Wrong key (folds to a different commit byte).
    let mut k = [0x42; 32];
    k[0] = 0x43;
    assert_eq!(MockSealer::new(k).open(ctx, &fetched), Err(SealError::Open));
}

// ── Journal evidence-chain integration (real pipeline → vocabulary-gated log) ──
//
// `src/journal.rs` unit-tests the log in ISOLATION, with hand-built fixtures
// ([0xAB; 32] roots, `b"mock-cid"` CIDs, [0xCD; 32] txids) that never come from
// the pipeline. This wires the ACTUAL offline round-trip into the journal: it
// seals a real PBM0 manifest, wraps it in a PBP0 package, uploads it to a
// `MockBackend`, and records each of the four evidence stages from the bytes the
// round-trip actually produced —
//
//   * `manifest_root` = [`MockHasher`] over the *uploaded package's* committed
//                       prefix (the exact value the signer would anchor),
//   * CID             = the `MockBackend::put_car` locator,
//   * `txid`          = [`MockHasher`] over the carrying zero-value DATA0 tx,
//                       which — via `extract_anchor` — decodes back to the same
//                       real `manifest_root`,
//   * `DealInfo`      = the backend's own `deal_status` probe.
//
// It then asserts the vocabulary gate ([`Journal::render_is_clean`] + the
// verbatim [`ANCHOR_CAVEAT`]) over that REAL output, and that an out-of-order
// stage record is rejected with a typed error.
//
// HONESTY: `MockSealer` / `MockHasher` / `MockBackend` are ZERO-crypto test
// doubles (see their module docs). This proves the *wiring and the gate*, never
// a confidentiality, integrity, or durability property. designed != built !=
// booted.

/// Lowercase hex of the first 8 bytes — mirrors the journal render's private
/// `hex_prefix` locator-shortening, so a test can assert a rendered line carries
/// the REAL round-trip bytes and not a hand-built fixture.
fn hex8(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// A 36-byte CIDv1-shaped locator (`0x01 ‖ raw-codec ‖ 0x12 0x20 ‖ digest[32]`)
/// derived deterministically from the backend's locator bytes. Shapes the
/// `manifest_cid` slot to the right length WITHOUT claiming a real sha2-256 CID
/// (this crate has no real hashing); the locator is unsigned and carries zero
/// integrity weight either way (§2/§4/§6).
fn cidv1_from(locator: &[u8]) -> [u8; bloch_data::anchor::CID_LEN] {
    let d = MockHasher::new().digest(DOMAIN_BLOB, locator);
    let mut cid = [0u8; bloch_data::anchor::CID_LEN];
    cid[..4].copy_from_slice(&[0x01, 0x55, 0x12, 0x20]); // cidv1 ‖ raw ‖ sha2-256 ‖ len-32
    cid[4..].copy_from_slice(&d);
    cid
}

/// Deterministic stand-in for the carrying Bloch transaction's txid: a
/// [`MockHasher`] digest over a canonical serialization of the tx that holds the
/// DATA0 envelope. The real base derives a txid by double-SHA over the wire tx;
/// here it is a pure function of the round-tripped anchor bytes (which embed the
/// real `manifest_root`), so it is genuinely "the txid this round-trip produced"
/// in the offline model — NOT a fixed [0xCD; 32] fixture. Zero security weight.
fn txid_of(tx: &Tx) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(&tx.version.to_le_bytes());
    for i in &tx.inputs {
        buf.extend_from_slice(&i.prev_txid);
        buf.extend_from_slice(&i.prev_index.to_le_bytes());
    }
    for o in &tx.outputs {
        buf.extend_from_slice(&o.value.to_le_bytes());
        buf.extend_from_slice(&(o.script_pubkey.len() as u64).to_le_bytes());
        buf.extend_from_slice(&o.script_pubkey);
    }
    buf.extend_from_slice(&tx.locktime.to_le_bytes());
    MockHasher::new().digest(0x00, &buf)
}

/// Run seal → package → put(MockBackend) → build+round-trip the DATA0 anchor tx,
/// returning every REAL byte string the journal stages need. Shared by both
/// integration tests so the "in order" and "out of order" cases drive the
/// identical pipeline output.
struct RoundTrip {
    namespace_id: [u8; 32],
    manifest_root: [u8; 32],
    entry_count: u64,
    cid: Cid,
    size: u64,
    txid: [u8; 32],
    sequence: u64,
}

fn drive_pipeline() -> RoundTrip {
    let ctx: &[u8] = b"postern-backup/manifest/v1";
    let sealer = MockSealer::new([0x42; 32]);
    let hasher = MockHasher::new();
    let mut backend = MockBackend::new();

    // seal → package → put(MockBackend)
    let manifest = sample_manifest();
    let entry_count = manifest.entries.len() as u64;
    let manifest_bytes = manifest.encode().unwrap();
    let sealed = sealer.seal(ctx, &manifest_bytes).unwrap();
    let package = Package {
        kdf_tier: TIER_DEFAULT,
        salt: [0x7E; 16],
        sealed_manifest: sealed,
        pk: vec![0x01; 8],  // slot, filled by the out-of-scope signer
        sig: vec![0x02; 16], // slot, filled by the out-of-scope signer
    };
    let package_bytes = package.encode().unwrap();
    let size = package_bytes.len() as u64;
    let cid = backend.put_car(&package_bytes).unwrap();

    // The REAL manifest_root the signer would anchor: MockHasher over the
    // uploaded package's committed prefix (NOT a [0xAB; 32] fixture).
    let manifest_root = hasher.manifest_root(&package).unwrap();

    // Build the DATA0 anchor tx and round-trip it back out: the decoded anchor
    // must carry the SAME real manifest_root the package produced.
    let namespace_id = [0x11; 32];
    let sequence = 0; // genesis
    let envelope = AnchorEnvelope {
        namespace_id,
        sequence,
        prev_root: [0u8; 32],
        manifest_root,
        signer_commit: hasher.digest(DOMAIN_BLOB, &package.pk),
        manifest_cid: cidv1_from(cid.as_bytes()),
    };
    let carry = Tx {
        version: 1,
        inputs: vec![TxIn { prev_txid: [0x00; 32], prev_index: 0 }],
        outputs: vec![TxOut { value: 0, script_pubkey: envelope.encode() }],
        locktime: 0,
    };
    let (_, decoded) = extract_anchor(&carry).expect("carry tx must carry the anchor");
    assert_eq!(decoded, envelope, "anchor must round-trip out of the carrying tx");
    assert_eq!(
        decoded.manifest_root, manifest_root,
        "the anchored root must be the real pipeline root, byte-for-byte"
    );
    let txid = txid_of(&carry);

    RoundTrip { namespace_id, manifest_root, entry_count, cid, size, txid, sequence }
}

#[test]
fn journal_records_the_real_pipeline_round_trip() {
    let rt = drive_pipeline();

    let mut journal = Journal::new(rt.namespace_id);

    // Sealed — from the real manifest_root + entry_count.
    journal
        .append(1, Evidence::Sealed { manifest_root: rt.manifest_root, entry_count: rt.entry_count })
        .unwrap();
    // Uploaded — from the real MockBackend CID + package size.
    journal
        .append(
            2,
            Evidence::Uploaded {
                cid: rt.cid.clone(),
                size: rt.size,
                provider_ref: None,
                observed_unix: 1_700_000_100,
            },
        )
        .unwrap();
    // Anchored — from the real carrying-tx txid + genesis sequence.
    journal
        .append(
            3,
            Evidence::Anchored {
                txid: rt.txid,
                sequence: rt.sequence,
                depth: AnchorDepth::Unconfirmed,
            },
        )
        .unwrap();
    // DealObserved — from the backend's own deal_status probe: put the real CID,
    // set a reported deal on it, then observe it back through the seam.
    let deal =
        DealInfo { deal_id: Some(42), provider: "f01234".to_string(), end_epoch: Some(5_000_000) };
    let mut backend = MockBackend::new();
    let stored = backend.put_car(b"sealed-package-car").unwrap();
    backend.set_deal_status(&stored, DealStatus::DealActive(vec![deal.clone()]));
    let observed = match backend.deal_status(&stored).unwrap() {
        DealStatus::DealActive(mut deals) => deals.remove(0),
        other => panic!("expected a reported deal, got {other:?}"),
    };
    assert_eq!(observed, deal);
    journal.append(4, Evidence::DealObserved(observed)).unwrap();

    assert_eq!(journal.highest_stage(), Some(Stage::DealObserved));
    assert_eq!(journal.records().len(), 4);

    // ── the render is wired to the REAL round-trip bytes, not fixtures ────
    let lines = journal.render();
    assert_eq!(lines.len(), 4);
    assert!(lines[0].starts_with("sealed locally"));
    assert!(
        lines[0].contains(&hex8(&rt.manifest_root)),
        "sealed line must carry the real manifest_root: {}",
        lines[0]
    );
    assert!(lines[1].starts_with("uploaded (provider ack, CID "));
    assert!(
        lines[1].contains(&hex8(rt.cid.as_bytes())),
        "uploaded line must carry the real CID: {}",
        lines[1]
    );
    assert!(lines[2].starts_with("anchored (tx "));
    assert!(
        lines[2].contains(&hex8(&rt.txid)),
        "anchored line must carry the real txid: {}",
        lines[2]
    );
    assert!(lines[3].starts_with("deal observed (dealId 42"));

    // ── vocabulary gate over the REAL output ─────────────────────────────
    assert!(journal.render_is_clean(), "render leaked a forbidden claim");
    let joined = lines.join("\n").to_ascii_lowercase();
    for w in FORBIDDEN_CLAIMS {
        assert!(!joined.contains(w), "render contained forbidden word {w:?}");
    }
    // The verbatim anchor caveat is stamped on the anchor line (byte-for-byte).
    assert!(
        lines[2].contains(ANCHOR_CAVEAT),
        "anchor line must emit the verbatim ANCHOR_CAVEAT: {}",
        lines[2]
    );
    assert!(lines[2].contains("k=4, 51%-attackable"));
    assert!(lines[2].contains("not finality."));
}

#[test]
fn journal_rejects_out_of_order_stage_from_the_real_pipeline() {
    // Same real pipeline output, but the caller tries to record the anchor
    // BEFORE the upload ack. The fail-safe ordering (§7) rejects it with a typed
    // error and leaves the append-only log untouched.
    let rt = drive_pipeline();

    let mut journal = Journal::new(rt.namespace_id);
    journal
        .append(1, Evidence::Sealed { manifest_root: rt.manifest_root, entry_count: rt.entry_count })
        .unwrap();

    // Anchored (real txid) recorded before any Uploaded ack: rejected.
    let anchored = Evidence::Anchored {
        txid: rt.txid,
        sequence: rt.sequence,
        depth: AnchorDepth::Unconfirmed,
    };
    assert_eq!(
        journal.append(2, anchored),
        Err(JournalError::MissingPrerequisite { got: Stage::Anchored, needs: Stage::Uploaded })
    );
    assert_eq!(journal.records().len(), 1, "a rejected record must not mutate the log");

    // The same bytes, recorded in the correct fail-safe order, append fine —
    // proving the rejection was about ordering, not about the payload.
    journal
        .append(
            2,
            Evidence::Uploaded {
                cid: rt.cid.clone(),
                size: rt.size,
                provider_ref: None,
                observed_unix: 5,
            },
        )
        .unwrap();
    journal
        .append(
            3,
            Evidence::Anchored {
                txid: rt.txid,
                sequence: rt.sequence,
                depth: AnchorDepth::Unconfirmed,
            },
        )
        .unwrap();
    assert_eq!(journal.highest_stage(), Some(Stage::Anchored));
}
