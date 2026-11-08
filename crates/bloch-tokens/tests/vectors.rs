//! Golden byte-for-byte wire vectors, pinned to the TKV0 layout tables in
//! `SPEC.md` (§1–§2).
//!
//! Every golden vector below is HAND-WRITTEN HEX transcribed from the spec
//! table — never produced by calling `encode()` (which would make the test
//! tautological). If the spec table and the code ever disagree, these tests
//! fail. Reject vectors are likewise literal bytes.

use bloch_tokens::envelope::{
    decode_envelope_output, EnvelopeError, TokenOp, TxOut, ENVELOPE_MAGIC, ENVELOPE_VERSION,
    FLAG_MINT_CLOSED,
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

// ── Golden ISSUE vector (SPEC.md §2) ─────────────────────────────────────────
//
// Hand-written from the §1.1/§1.2 tables:
//   magic "TKV0"          54 4B 56 30
//   version               00
//   op ISSUE              01
//   decimals 8            08
//   flags mint-closed     01
//   supply 21_000_000 LE  40 6F 40 01 00 00 00 00
//   sym_len 4             04
//   symbol "ACME"         41 43 4D 45
//   name_len 10           0A
//   name "Acme Token"     41 63 6D 65 20 54 6F 6B 65 6E
const GOLDEN_ISSUE_HEX: &str =
    "544B5630 00 01 08 01 406F400100000000 04 41434D45 0A 41636D6520546F6B656E";

fn golden_issue_op() -> TokenOp {
    TokenOp::Issue {
        decimals: 8,
        flags: FLAG_MINT_CLOSED,
        supply: 21_000_000,
        symbol: "ACME".into(),
        name: "Acme Token".into(),
    }
}

// ── Golden TRANSFER vector (SPEC.md §2) ──────────────────────────────────────
//
//   magic "TKV0"          54 4B 56 30
//   version               00
//   op TRANSFER           02
//   token_id 00..1F       00 01 02 ... 1F   (32 bytes)
//   n = 2                 02
//   vout 0 LE             00 00 00 00
//   amount 1000 LE        E8 03 00 00 00 00 00 00
//   vout 2 LE             02 00 00 00
//   amount 45 LE          2D 00 00 00 00 00 00 00
const GOLDEN_TRANSFER_HEX: &str = "544B5630 00 02 \
     000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F \
     02 00000000 E803000000000000 02000000 2D00000000000000";

fn golden_transfer_token_id() -> [u8; 32] {
    let mut id = [0u8; 32];
    for (i, b) in id.iter_mut().enumerate() {
        *b = i as u8;
    }
    id
}

fn golden_transfer_op() -> TokenOp {
    TokenOp::Transfer {
        token_id: golden_transfer_token_id(),
        assignments: vec![(0, 1000), (2, 45)],
    }
}

// ── Layout pinning: field offsets straight from the spec table ───────────────

#[test]
fn issue_vector_matches_spec_table_offsets() {
    let v = hex(GOLDEN_ISSUE_HEX);
    // Total length: 18 + S + N with S=4, N=10 (SPEC.md §1.2).
    assert_eq!(v.len(), 18 + 4 + 10);
    assert_eq!(&v[0..4], b"TKV0", "magic at offset 0");
    assert_eq!(&v[0..4], &ENVELOPE_MAGIC, "code constant must equal spec magic");
    assert_eq!(v[4], 0x00, "version at offset 4");
    assert_eq!(v[4], ENVELOPE_VERSION, "code constant must equal spec version");
    assert_eq!(v[5], 0x01, "op=ISSUE at offset 5");
    assert_eq!(v[6], 8, "decimals at offset 6");
    assert_eq!(v[7], 0x01, "flags at offset 7 (bit0 = mint-closed, mandatory)");
    assert_eq!(v[7], FLAG_MINT_CLOSED, "code constant must equal spec flag");
    assert_eq!(
        u64::from_le_bytes(v[8..16].try_into().unwrap()),
        21_000_000,
        "supply u64-LE at offset 8"
    );
    assert_eq!(v[16], 4, "sym_len at offset 16");
    assert_eq!(&v[17..21], b"ACME", "symbol at offset 17");
    assert_eq!(v[21], 10, "name_len at offset 17+S");
    assert_eq!(&v[22..32], b"Acme Token", "name at offset 18+S");
}

#[test]
fn transfer_vector_matches_spec_table_offsets() {
    let v = hex(GOLDEN_TRANSFER_HEX);
    // Total length: 39 + 12·n with n=2 (SPEC.md §1.3).
    assert_eq!(v.len(), 39 + 12 * 2);
    assert_eq!(&v[0..4], b"TKV0", "magic at offset 0");
    assert_eq!(v[4], 0x00, "version at offset 4");
    assert_eq!(v[5], 0x02, "op=TRANSFER at offset 5");
    assert_eq!(&v[6..38], &golden_transfer_token_id()[..], "token_id at offset 6");
    assert_eq!(v[38], 2, "assignment count at offset 38");
    assert_eq!(
        u32::from_le_bytes(v[39..43].try_into().unwrap()),
        0,
        "first vout u32-LE at offset 39"
    );
    assert_eq!(
        u64::from_le_bytes(v[43..51].try_into().unwrap()),
        1000,
        "first amount u64-LE at offset 43"
    );
    assert_eq!(
        u32::from_le_bytes(v[51..55].try_into().unwrap()),
        2,
        "second vout u32-LE at offset 51"
    );
    assert_eq!(
        u64::from_le_bytes(v[55..63].try_into().unwrap()),
        45,
        "second amount u64-LE at offset 55"
    );
}

// ── Decode: hand-written bytes must yield exactly the expected fields ─────────

#[test]
fn issue_vector_decodes_to_expected_fields() {
    let decoded = TokenOp::decode(&hex(GOLDEN_ISSUE_HEX)).expect("golden ISSUE must decode");
    assert_eq!(decoded, golden_issue_op());
}

#[test]
fn transfer_vector_decodes_to_expected_fields() {
    let decoded = TokenOp::decode(&hex(GOLDEN_TRANSFER_HEX)).expect("golden TRANSFER must decode");
    assert_eq!(decoded, golden_transfer_op());
}

// ── Encode: the code must reproduce the hand-written bytes exactly ────────────

#[test]
fn issue_encode_reproduces_golden_bytes() {
    assert_eq!(
        golden_issue_op().encode(),
        hex(GOLDEN_ISSUE_HEX),
        "encode() diverged from the SPEC.md §1.2 layout table"
    );
}

#[test]
fn transfer_encode_reproduces_golden_bytes() {
    assert_eq!(
        golden_transfer_op().encode(),
        hex(GOLDEN_TRANSFER_HEX),
        "encode() diverged from the SPEC.md §1.3 layout table"
    );
}

// ── Decode-reject vectors: literal bytes, typed errors, no panics ─────────────

#[test]
fn reject_vectors_each_fail_with_the_expected_typed_error() {
    // (name, literal hex, expected error) — every wire-level malformed class
    // named in SPEC.md §4.
    let cases: &[(&str, &str, EnvelopeError)] = &[
        ("empty input", "", EnvelopeError::Truncated),
        ("short of magic", "544B56", EnvelopeError::Truncated),
        ("bad magic (old BTKN)", "42544B4E 00 01", EnvelopeError::BadMagic),
        ("bad version 0x01", "544B5630 01 01", EnvelopeError::BadVersion(0x01)),
        ("unknown op 0x03", "544B5630 00 03", EnvelopeError::UnknownOp(0x03)),
        ("decimals 19 (over cap 18)", "544B5630 00 01 13", EnvelopeError::BadDecimals(19)),
        ("flags 0x00 (mint-closed unset)", "544B5630 00 01 08 00", EnvelopeError::BadFlags(0)),
        ("flags 0x03 (reserved bit set)", "544B5630 00 01 08 03", EnvelopeError::BadFlags(3)),
        (
            "zero supply",
            "544B5630 00 01 08 01 0000000000000000",
            EnvelopeError::BadAmount,
        ),
        (
            "sym_len 0",
            "544B5630 00 01 08 01 0100000000000000 00",
            EnvelopeError::BadSymbol,
        ),
        (
            "sym_len 9 (over cap 8)",
            "544B5630 00 01 08 01 0100000000000000 09 414141414141414141",
            EnvelopeError::BadSymbol,
        ),
        (
            "lowercase symbol \"tok\"",
            "544B5630 00 01 08 01 0100000000000000 03 746F6B",
            EnvelopeError::BadSymbol,
        ),
        (
            "symbol with space \"T K\"",
            "544B5630 00 01 08 01 0100000000000000 03 54204B",
            EnvelopeError::BadSymbol,
        ),
        (
            "name_len 33 (over cap 32)",
            "544B5630 00 01 08 01 0100000000000000 01 54 21",
            EnvelopeError::BadName,
        ),
        (
            "name not UTF-8 (FF FE)",
            "544B5630 00 01 08 01 0100000000000000 01 54 02 FFFE",
            EnvelopeError::BadName,
        ),
        (
            "transfer truncated token_id",
            "544B5630 00 02 111111111111111111111111111111",
            EnvelopeError::Truncated,
        ),
        (
            "transfer assignment count 0",
            "544B5630 00 02 \
             1111111111111111111111111111111111111111111111111111111111111111 \
             00",
            EnvelopeError::BadAssignmentCount(0),
        ),
        (
            "transfer assignment count 17 (over cap 16)",
            "544B5630 00 02 \
             1111111111111111111111111111111111111111111111111111111111111111 \
             11",
            EnvelopeError::BadAssignmentCount(17),
        ),
        (
            "zero transfer amount",
            "544B5630 00 02 \
             1111111111111111111111111111111111111111111111111111111111111111 \
             01 00000000 0000000000000000",
            EnvelopeError::BadAmount,
        ),
        (
            "duplicate vout 5",
            "544B5630 00 02 \
             1111111111111111111111111111111111111111111111111111111111111111 \
             02 05000000 0100000000000000 05000000 0100000000000000",
            EnvelopeError::DuplicateVout(5),
        ),
    ];

    for (name, hx, expected) in cases {
        let got = TokenOp::decode(&hex(hx));
        assert_eq!(got, Err(expected.clone()), "reject vector {name:?}");
    }
}

#[test]
fn reject_truncated_and_trailing_variants_of_the_golden_vectors() {
    for (name, hx) in [("ISSUE", GOLDEN_ISSUE_HEX), ("TRANSFER", GOLDEN_TRANSFER_HEX)] {
        let full = hex(hx);

        // Every strict prefix must fail (truncation at any point).
        for cut in 0..full.len() {
            let err = TokenOp::decode(&full[..cut])
                .expect_err("every strict prefix of a golden vector must be rejected");
            assert!(
                matches!(err, EnvelopeError::Truncated | EnvelopeError::BadMagic),
                "{name} truncated at {cut}: unexpected {err:?}"
            );
        }

        // One extra byte after a complete envelope must fail.
        let mut trailing = full.clone();
        trailing.push(0x00);
        assert_eq!(
            TokenOp::decode(&trailing),
            Err(EnvelopeError::TrailingBytes),
            "{name} + trailing byte"
        );
    }
}

#[test]
fn reject_envelope_on_nonzero_value_output() {
    // Valid golden bytes on an output that carries value: rejected at the
    // output level (envelopes must never lock BLCH behind them).
    let out = TxOut {
        value: 5_000,
        script_pubkey: hex(GOLDEN_ISSUE_HEX),
    };
    assert_eq!(
        decode_envelope_output(&out),
        Err(EnvelopeError::NonZeroValue(5_000))
    );
}

/// Compile-time exhaustiveness guard: if a new `EnvelopeError` variant is
/// added to the wire layer, this match stops compiling until the reject
/// vectors above are extended to cover it.
#[allow(dead_code)]
fn every_envelope_error_class_has_a_reject_vector(e: EnvelopeError) {
    match e {
        EnvelopeError::BadMagic => {}            // "bad magic (old BTKN)"
        EnvelopeError::BadVersion(_) => {}       // "bad version 0x01"
        EnvelopeError::UnknownOp(_) => {}        // "unknown op 0x03"
        EnvelopeError::Truncated => {}           // "empty input" / prefixes
        EnvelopeError::TrailingBytes => {}       // golden + trailing byte
        EnvelopeError::BadSymbol => {}           // sym_len 0 / 9 / lowercase / space
        EnvelopeError::BadName => {}             // name_len 33 / non-UTF-8
        EnvelopeError::BadDecimals(_) => {}      // decimals 19
        EnvelopeError::BadFlags(_) => {}         // flags 0x00 / 0x03
        EnvelopeError::BadAmount => {}           // zero supply / zero amount
        EnvelopeError::BadAssignmentCount(_) => {} // count 0 / 17
        EnvelopeError::DuplicateVout(_) => {}    // duplicate vout 5
        EnvelopeError::NonZeroValue(_) => {}     // envelope on value output
    }
}
