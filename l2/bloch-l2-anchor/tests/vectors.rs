//! Golden byte-for-byte wire vectors, pinned to the L2V0 COMMIT anchor
//! layout in `docs/specs/BLOCH-L2-EVM-DESIGN.md` §1 "Interfaces / formats"
//! (mirrors `bloch-tokens/tests/vectors.rs`, which pins TKV0).
//!
//! Every golden vector below is HAND-WRITTEN HEX transcribed from the spec
//! layout — never produced by calling `encode()` (which would make the test
//! tautological). If the spec layout and the code ever disagree, these tests
//! fail. Reject vectors are likewise literal bytes.

use bloch_l2_anchor::envelope::{
    decode_anchor_output, link, AnchorEnvelope, EnvelopeError, LinkError, TxOut, ENVELOPE_LEN,
    ENVELOPE_MAGIC, ENVELOPE_VERSION,
};

/// Parse a whitespace-tolerant hex string into bytes. Test-only helper; the
/// hex literals themselves are the source of truth.
fn hex(s: &str) -> Vec<u8> {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(compact.len() % 2 == 0, "odd-length hex literal");
    (0..compact.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&compact[i..i + 2], 16).expect("bad hex literal"))
        .collect()
}

// ── Golden COMMIT vector ──────────────────────────────────────────────────────
//
// Hand-written from the design-doc layout (fixed 173 bytes):
//   magic "L2V0"            4C 32 56 30
//   version                 00
//   rollup_id 00..1F        00 01 02 ... 1F                (32 bytes)
//   batch_index 7 u64-LE    07 00 00 00 00 00 00 00
//   prev_state_root AA*32   AA ... AA                      (32 bytes)
//   new_state_root  BB*32   BB ... BB                      (32 bytes)
//   da_commitment   CC*32   CC ... CC                      (32 bytes)
//   vkey_hash       DD*32   DD ... DD                      (32 bytes)
const GOLDEN_COMMIT_HEX: &str = "4C325630 00 \
     000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F \
     0700000000000000 \
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \
     BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB \
     CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC \
     DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";

fn golden_rollup_id() -> [u8; 32] {
    let mut id = [0u8; 32];
    for (i, b) in id.iter_mut().enumerate() {
        *b = i as u8;
    }
    id
}

fn golden_commit() -> AnchorEnvelope {
    AnchorEnvelope {
        rollup_id: golden_rollup_id(),
        batch_index: 7,
        prev_state_root: [0xAA; 32],
        new_state_root: [0xBB; 32],
        da_commitment: [0xCC; 32],
        vkey_hash: [0xDD; 32],
    }
}

// ── Layout pinning: field offsets straight from the spec ─────────────────────

#[test]
fn commit_vector_matches_spec_offsets() {
    let v = hex(GOLDEN_COMMIT_HEX);
    // Total length: fixed 173 bytes = 4 + 1 + 32 + 8 + 32 + 32 + 32 + 32.
    assert_eq!(v.len(), 173);
    assert_eq!(v.len(), ENVELOPE_LEN, "code constant must equal spec length");
    assert_eq!(&v[0..4], b"L2V0", "magic at offset 0");
    assert_eq!(&v[0..4], &ENVELOPE_MAGIC, "code constant must equal spec magic");
    assert_eq!(&v[0..4], &[0x4C, 0x32, 0x56, 0x30], "magic bytes are 4C 32 56 30");
    assert_eq!(v[4], 0x00, "version at offset 4");
    assert_eq!(v[4], ENVELOPE_VERSION, "code constant must equal spec version");
    assert_eq!(&v[5..37], &golden_rollup_id()[..], "rollup_id at offset 5");
    assert_eq!(
        u64::from_le_bytes(v[37..45].try_into().unwrap()),
        7,
        "batch_index u64-LE at offset 37"
    );
    assert_eq!(&v[45..77], &[0xAA; 32], "prev_state_root at offset 45");
    assert_eq!(&v[77..109], &[0xBB; 32], "new_state_root at offset 77");
    assert_eq!(&v[109..141], &[0xCC; 32], "da_commitment at offset 109");
    assert_eq!(&v[141..173], &[0xDD; 32], "vkey_hash at offset 141");
}

// ── Decode: hand-written bytes must yield exactly the expected fields ─────────

#[test]
fn commit_vector_decodes_to_expected_fields() {
    let decoded =
        AnchorEnvelope::decode(&hex(GOLDEN_COMMIT_HEX)).expect("golden COMMIT must decode");
    assert_eq!(decoded, golden_commit());
}

// ── Encode: the code must reproduce the hand-written bytes exactly ────────────

#[test]
fn commit_encode_reproduces_golden_bytes() {
    assert_eq!(
        golden_commit().encode(),
        hex(GOLDEN_COMMIT_HEX),
        "encode() diverged from the BLOCH-L2-EVM-DESIGN §1 anchor layout"
    );
}

// ── Decode-reject vectors: literal bytes, typed errors, no panics ─────────────

#[test]
fn reject_vectors_each_fail_with_the_expected_typed_error() {
    let cases: &[(&str, &str, EnvelopeError)] = &[
        ("empty input", "", EnvelopeError::Truncated),
        ("short of magic", "4C3256", EnvelopeError::Truncated),
        ("bad magic (TKV0)", "544B5630 00", EnvelopeError::BadMagic),
        ("bad magic (L2V1 ASCII)", "4C325631 00", EnvelopeError::BadMagic),
        ("bad version 0x01", "4C325630 01", EnvelopeError::BadVersion(0x01)),
        ("bad version 0xFF", "4C325630 FF", EnvelopeError::BadVersion(0xFF)),
        (
            "header only (no fields)",
            "4C325630 00",
            EnvelopeError::Truncated,
        ),
        (
            "truncated mid-rollup_id",
            "4C325630 00 00010203",
            EnvelopeError::Truncated,
        ),
    ];

    for (name, hx, expected) in cases {
        let got = AnchorEnvelope::decode(&hex(hx));
        assert_eq!(got, Err(expected.clone()), "reject vector {name:?}");
    }
}

#[test]
fn reject_truncated_and_trailing_variants_of_the_golden_vector() {
    let full = hex(GOLDEN_COMMIT_HEX);

    // Every strict prefix must fail (truncation at any point).
    for cut in 0..full.len() {
        let err = AnchorEnvelope::decode(&full[..cut])
            .expect_err("every strict prefix of the golden vector must be rejected");
        assert!(
            matches!(err, EnvelopeError::Truncated | EnvelopeError::BadMagic),
            "truncated at {cut}: unexpected {err:?}"
        );
    }

    // One extra byte after a complete envelope must fail (exact length: 174
    // bytes is malformed).
    let mut trailing = full.clone();
    trailing.push(0x00);
    assert_eq!(
        AnchorEnvelope::decode(&trailing),
        Err(EnvelopeError::TrailingBytes),
        "golden + trailing byte"
    );
}

#[test]
fn reject_envelope_on_nonzero_value_output() {
    // Valid golden bytes on an output that carries value: rejected at the
    // output level (TKV0 caveat E.1 — envelopes must never lock BLCH).
    let out = TxOut { value: 5_000, script_pubkey: hex(GOLDEN_COMMIT_HEX) };
    assert_eq!(decode_anchor_output(&out), Err(EnvelopeError::NonZeroValue(5_000)));
}

/// Compile-time exhaustiveness guard: if a new `EnvelopeError` variant is
/// added to the wire layer, this match stops compiling until the reject
/// vectors above are extended to cover it.
#[allow(dead_code)]
fn every_envelope_error_class_has_a_reject_vector(e: EnvelopeError) {
    match e {
        EnvelopeError::BadMagic => {}      // "bad magic (TKV0)" / "(L2V1)"
        EnvelopeError::BadVersion(_) => {} // "bad version 0x01" / "0xFF"
        EnvelopeError::Truncated => {}     // "empty input" / prefixes
        EnvelopeError::TrailingBytes => {} // golden + trailing byte
        EnvelopeError::NonZeroValue(_) => {} // envelope on value output
    }
}

// ── Chain linkage over golden-shaped anchors ──────────────────────────────────

#[test]
fn golden_vector_links_to_its_hand_built_successor() {
    // Successor of the golden anchor, hand-written: batch_index 8, its
    // prev_state_root is the golden new_state_root (BB*32).
    let successor_hex: &str = "4C325630 00 \
         000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F \
         0800000000000000 \
         BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB \
         EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE \
         CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC \
         DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";
    let prev = AnchorEnvelope::decode(&hex(GOLDEN_COMMIT_HEX)).unwrap();
    let next = AnchorEnvelope::decode(&hex(successor_hex)).unwrap();
    assert_eq!(link(&prev, &next), Ok(()));
    // Reversed order is NOT canonical.
    assert_eq!(
        link(&next, &prev),
        Err(LinkError::NonConsecutiveIndex { prev: 8, next: 7 })
    );
}
