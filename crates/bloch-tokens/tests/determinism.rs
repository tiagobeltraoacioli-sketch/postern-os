//! Integration tests proving the two properties the standard actually rests
//! on, since it is OFF-consensus (zero consensus change, no fork):
//!
//! 1. **Determinism** — independent indexers fed the same chain end in
//!    identical state (structurally and in `Debug` form — every container is
//!    a `BTreeMap`, so representation order is canonical), including across
//!    deep reorgs handled by rewind + replay.
//! 2. **Adversarial robustness** — malformed token traffic can never panic
//!    the indexer and never yields a propagating error: applying a
//!    transaction is total (`ApplyOutcome` has no error variant), every
//!    malformed class maps to a typed no-op, and the token layer never
//!    invalidates or perturbs a chain transaction (BLCH values are never
//!    even modeled).

use bloch_tokens::chain::{ChainTx, OutPoint};
use bloch_tokens::envelope::{TokenOp, TxOut, ENVELOPE_MAGIC, FLAG_MINT_CLOSED};
use bloch_tokens::indexer::Indexer;
use bloch_tokens::state::{NoOpReason, TokenEffect, TokenState};
use bloch_tokens::stream::{BlockSource, MockChain};

// ── builders ─────────────────────────────────────────────────────────────────

fn txid(n: u8) -> [u8; 32] {
    [n; 32]
}

fn pt(tx: u8, vout: u32) -> OutPoint {
    OutPoint { txid: txid(tx), vout }
}

fn spk(n: u8) -> Vec<u8> {
    vec![n; 20]
}

/// Ordinary spendable output (20-byte pubkey-hash-like script).
fn pay(value: u64, script: Vec<u8>) -> TxOut {
    TxOut { value, script_pubkey: script }
}

/// Zero-value envelope output for a valid op.
fn env(op: &TokenOp) -> TxOut {
    TxOut { value: 0, script_pubkey: op.encode() }
}

/// Envelope-magic-bearing output with arbitrary (possibly malformed) bytes.
fn env_raw(value: u64, script: Vec<u8>) -> TxOut {
    assert!(script.starts_with(&ENVELOPE_MAGIC), "test builder misuse");
    TxOut { value, script_pubkey: script }
}

fn ctx(id: u8, inputs: Vec<OutPoint>, outputs: Vec<TxOut>) -> ChainTx {
    ChainTx { txid: txid(id), inputs, outputs }
}

fn issue(symbol: &str, supply: u64) -> TokenOp {
    TokenOp::Issue {
        decimals: 2,
        flags: FLAG_MINT_CLOSED,
        supply,
        symbol: symbol.into(),
        name: format!("{symbol} token"),
    }
}

fn transfer(token: u8, assignments: Vec<(u32, u64)>) -> TokenOp {
    TokenOp::Transfer { token_id: txid(token), assignments }
}

const ALICE: u8 = 0xA1;
const BOB: u8 = 0xB2;
const CAROL: u8 = 0xC3;
const DAVE: u8 = 0xD4;

/// A busy but well-formed history: two issues, split transfers with explicit
/// change assignments, plain BLCH traffic, a full-balance move.
fn baseline_chain() -> MockChain {
    let mut c = MockChain::new();
    // h0: coinbase-ish BLCH + issue ACME (token_id = txid(2)), supply 1000
    //     to output 0 (alice).
    c.append(vec![
        ctx(1, vec![], vec![pay(50_000, spk(0x50))]),
        ctx(2, vec![], vec![pay(1, spk(ALICE)), env(&issue("ACME", 1000))]),
    ]);
    // h1: split — 400 ACME to bob, explicit 600 change back to alice.
    c.append(vec![ctx(
        3,
        vec![pt(2, 0)],
        vec![
            pay(1, spk(BOB)),
            pay(1, spk(ALICE)),
            env(&transfer(2, vec![(0, 400), (1, 600)])),
        ],
    )]);
    // h2: plain BLCH spend, no token meaning.
    c.append(vec![ctx(
        4,
        vec![pt(1, 0)],
        vec![pay(49_000, spk(0x51)), pay(900, spk(0x52))],
    )]);
    // h3: second token ZZ9 (token_id = txid(5)) to carol; and alice's 600
    //     ACME moved whole to dave (full assignment, nothing burns).
    c.append(vec![
        ctx(5, vec![pt(4, 1)], vec![pay(100, spk(CAROL)), env(&issue("ZZ9", 7))]),
        ctx(
            6,
            vec![pt(3, 1)],
            vec![pay(1, spk(DAVE)), env(&transfer(2, vec![(0, 600)]))],
        ),
    ]);
    // h4: split bob's 400: 150 to carol, explicit 250 change to bob.
    c.append(vec![ctx(
        7,
        vec![pt(3, 0)],
        vec![
            pay(1, spk(CAROL)),
            pay(1, spk(BOB)),
            env(&transfer(2, vec![(0, 150), (1, 250)])),
        ],
    )]);
    // h5: more plain traffic.
    c.append(vec![ctx(8, vec![pt(4, 0)], vec![pay(48_500, spk(0x53))])]);
    c
}

fn synced(chain: &MockChain) -> Indexer {
    let mut ix = Indexer::new();
    ix.sync(chain).expect("sync must succeed");
    ix
}

// ── 1. two independent indexers agree ────────────────────────────────────────

#[test]
fn independent_indexers_reach_identical_state() {
    // Two identically-built chains (MockChain hashing is deterministic) and
    // two indexers with DIFFERENT sync cadences — one batch sync, one sync
    // after every block. Cadence is an implementation detail and must not
    // leak into state.
    let chain = baseline_chain();
    let a = synced(&chain);

    let full = baseline_chain();
    let mut partial = MockChain::new();
    let mut b = Indexer::new();
    for h in 0..=full.tip_height().unwrap() {
        partial.append(full.block_by_height(h).unwrap().transactions);
        b.sync(&partial).expect("incremental sync must succeed");
    }

    assert_eq!(a.state(), b.state(), "structural state must agree");
    assert_eq!(a.journal(), b.journal(), "hash journals must agree");
    assert_eq!(
        format!("{:?}", a.state()),
        format!("{:?}", b.state()),
        "canonical (BTreeMap-ordered) representation must be identical"
    );

    // Sanity: the history actually did something.
    let acme = txid(2);
    assert_eq!(a.state().tokens().len(), 2);
    assert_eq!(a.state().balance(&spk(DAVE), &acme), 600);
    assert_eq!(a.state().balance(&spk(CAROL), &acme), 150);
    assert_eq!(a.state().balance(&spk(BOB), &acme), 250);
    assert_eq!(a.state().balance(&spk(CAROL), &txid(5)), 7);
    assert_eq!(a.state().token(&acme).unwrap().circulating(), 1000);
}

// ── 2. replay-after-reorg equivalence (deep fork) ────────────────────────────

#[test]
fn deep_reorg_replays_to_exactly_the_fresh_state() {
    let mut chain = baseline_chain();

    // Indexer A lives through the original history…
    let mut a = synced(&chain);
    assert!(a.state().tokens().contains_key(&txid(5)), "ZZ9 exists pre-reorg");

    // …then the chain reorgs at height 1: everything above height 0 is
    // replaced by a branch with different txids, different amounts, and its
    // own token (NEW = txid(31)) that never existed on the old branch.
    chain.replace_suffix(
        1,
        vec![
            // h1': alice moves only 100 to bob, 900 change to herself.
            vec![ctx(
                30,
                vec![pt(2, 0)],
                vec![
                    pay(1, spk(BOB)),
                    pay(1, spk(ALICE)),
                    env(&transfer(2, vec![(0, 100), (1, 900)])),
                ],
            )],
            // h2': a token that never existed on the old branch.
            vec![ctx(31, vec![], vec![pay(9, spk(DAVE)), env(&issue("NEW", 555))])],
            // h3': plain traffic.
            vec![ctx(32, vec![pt(1, 0)], vec![pay(50_000, spk(0x54))])],
            // h4': NEW moves 500 to carol, 55 change to dave.
            vec![ctx(
                33,
                vec![pt(31, 0)],
                vec![
                    pay(1, spk(CAROL)),
                    pay(1, spk(DAVE)),
                    env(&transfer(31, vec![(0, 500), (1, 55)])),
                ],
            )],
        ],
    );

    let report = a.sync(&chain).expect("post-reorg sync must succeed");
    assert!(report.reorged);
    assert_eq!(report.rewound_to, Some(0), "only height 0 survived");

    // Indexer B never saw the orphaned branch.
    let b = synced(&chain);
    assert_eq!(a.state(), b.state(), "replay-after-reorg == never-saw-the-orphan");
    assert_eq!(a.journal(), b.journal());

    // The orphaned branch left no trace: ZZ9 (txid 5) is gone, NEW exists.
    assert!(!a.state().tokens().contains_key(&txid(5)));
    assert!(a.state().tokens().contains_key(&txid(31)));
    assert_eq!(a.state().balance(&spk(ALICE), &txid(2)), 900);
    assert_eq!(a.state().balance(&spk(CAROL), &txid(31)), 500);
}

// ── 3. adversarial stream: never panics, typed no-ops, chain untouched ───────

/// Every state-level malformed class named in SPEC.md §4, plus u64::MAX
/// supplies, in one stream. Returns (chain, expected effect per tx in order).
fn adversarial_chain() -> (MockChain, Vec<TokenEffect>) {
    use NoOpReason::*;
    use TokenEffect::*;

    let mut c = MockChain::new();
    let mut expect: Vec<TokenEffect> = Vec::new();

    // h0 — small token to over-assign later + u64::MAX-supply token.
    c.append(vec![
        ctx(9, vec![], vec![pay(1, spk(ALICE)), env(&issue("SMALL", 100))]),
        ctx(10, vec![], vec![pay(1, spk(ALICE)), env(&issue("MAX", u64::MAX))]),
    ]);
    expect.push(Issued { token_id: txid(9), supply: 100 });
    expect.push(Issued { token_id: txid(10), supply: u64::MAX });

    // h1 — the malformed parade. Every tx is chain-valid; only its token
    // interpretation is bad (or, for tx 11, resolved by first-wins).
    c.append(vec![
        // two valid envelopes: FIRST WINS (the issue) — deterministic, not
        // ambiguous; the second magic output is ignored.
        ctx(
            11,
            vec![],
            vec![
                pay(1, spk(BOB)),
                env(&issue("DUP", 5)),
                env(&transfer(10, vec![(0, 1)])),
            ],
        ),
        // envelope riding a NONZERO-value output: unusable (typed no-op).
        ctx(
            12,
            vec![],
            vec![env_raw(7, transfer(10, vec![(0, 1)]).encode()), pay(1, spk(BOB))],
        ),
        // transfer of a token_id that was never issued.
        ctx(13, vec![], vec![pay(1, spk(BOB)), env(&transfer(0xEE, vec![(0, 1)]))]),
        // over-assignment: spends the 100-unit SMALL coin, claims 150.
        ctx(
            14,
            vec![pt(9, 0)],
            vec![pay(1, spk(BOB)), env(&transfer(9, vec![(0, 150)]))],
        ),
        // malformed: bad version byte behind valid magic.
        ctx(15, vec![], vec![env_raw(0, b"TKV0\x09\x01".to_vec()), pay(1, spk(BOB))]),
        // malformed: truncated envelope (magic only).
        ctx(16, vec![], vec![env_raw(0, b"TKV0".to_vec()), pay(1, spk(BOB))]),
        // malformed: zero supply (wire-invalid even though chain-valid).
        ctx(
            17,
            vec![],
            vec![
                env_raw(0, {
                    let mut b = b"TKV0\x00\x01\x00\x01".to_vec(); // ver op decimals flags
                    b.extend_from_slice(&0u64.to_le_bytes()); // supply 0
                    b.extend_from_slice(b"\x01T\x00"); // sym "T", empty name
                    b
                }),
                pay(1, spk(BOB)),
            ],
        ),
        // ISSUE with no recipient: envelope is the only output.
        ctx(18, vec![], vec![env(&issue("ORPHAN", 3))]),
        // ISSUE whose envelope sits at output 0 (supply must ride output 0).
        ctx(22, vec![], vec![env(&issue("ZERO", 3)), pay(1, spk(BOB))]),
        // transfer assigning to a vout that does not exist.
        ctx(23, vec![], vec![pay(1, spk(BOB)), env(&transfer(10, vec![(9, 1)]))]),
        // transfer assigning to the envelope output itself (vout 1).
        ctx(24, vec![], vec![pay(1, spk(BOB)), env(&transfer(10, vec![(1, 1)]))]),
    ]);
    expect.push(Issued { token_id: txid(11), supply: 5 }); // first envelope won
    expect.push(NoOp(MalformedEnvelope)); // nonzero-value carrier
    expect.push(NoOp(UnknownToken));
    expect.push(NoOp(OverAssignment));
    expect.push(NoOp(MalformedEnvelope)); // bad version
    expect.push(NoOp(MalformedEnvelope)); // truncated
    expect.push(NoOp(MalformedEnvelope)); // zero supply
    expect.push(NoOp(IssueRecipientMissing));
    expect.push(NoOp(IssueRecipientMissing)); // envelope at output 0
    expect.push(NoOp(AssignmentOutOfRange)); // missing vout
    expect.push(NoOp(AssignmentOutOfRange)); // envelope vout

    // h2 — u64::MAX moves whole without overflow; an assignment list whose
    // sum overflows u64 is a typed no-op (not a wrap); a transfer against an
    // already-burned balance over-assigns.
    c.append(vec![
        ctx(
            19,
            vec![pt(10, 0)],
            vec![pay(1, spk(CAROL)), env(&transfer(10, vec![(0, u64::MAX)]))],
        ),
        ctx(
            20,
            vec![pt(19, 0)],
            vec![
                pay(1, spk(DAVE)),
                pay(1, spk(CAROL)),
                env(&transfer(10, vec![(0, u64::MAX), (1, 1)])),
            ],
        ),
        ctx(21, vec![], vec![pay(1, spk(DAVE)), env(&transfer(10, vec![(0, 1)]))]),
    ]);
    expect.push(Transferred { token_id: txid(10), assigned: u64::MAX });
    expect.push(NoOp(ArithmeticOverflow)); // and tx 20 burned what it spent
    expect.push(NoOp(OverAssignment)); // available 0 after the burn

    (c, expect)
}

/// The same chain with every envelope PAYLOAD stripped (values, inputs and
/// outputs untouched): the token-blind control.
fn strip_payloads(chain: &MockChain) -> MockChain {
    let mut c = MockChain::new();
    for h in 0..=chain.tip_height().expect("adversarial chain is nonempty") {
        let mut txs = chain.block_by_height(h).unwrap().transactions;
        for tx in &mut txs {
            for o in &mut tx.outputs {
                if o.script_pubkey.starts_with(&ENVELOPE_MAGIC) {
                    o.script_pubkey = spk(0x22);
                }
            }
        }
        c.append(txs);
    }
    c
}

#[test]
fn adversarial_stream_never_panics_and_every_bad_class_is_typed() {
    let (chain, expected) = adversarial_chain();

    // Pin every per-tx effect by walking the chain through the state
    // machine directly. Completing this loop at all proves "never panics";
    // the signature (`ApplyOutcome`, not `Result`) proves "never an error".
    let mut st = TokenState::new();
    let mut effects = Vec::new();
    for h in 0..=chain.tip_height().unwrap() {
        for tx in &chain.block_by_height(h).unwrap().transactions {
            effects.push(st.apply_tx(h, tx).effect);
        }
    }
    assert_eq!(effects.len(), expected.len());
    for (i, (got, want)) in effects.iter().zip(&expected).enumerate() {
        assert_eq!(got, want, "tx #{i}: effect mismatch");
    }

    // The indexer over the same chain reaches the same state (same rules,
    // block-driven path).
    let ix = synced(&chain);
    assert_eq!(ix.state(), &st);

    // Malformed traffic must not mint: SMALL, MAX, DUP only.
    assert_eq!(st.tokens().len(), 3);
    for ghost in [12u8, 13, 15, 16, 17, 18, 22] {
        assert!(!st.tokens().contains_key(&txid(ghost)), "ghost token {ghost}");
    }
    // Burned color stays burned: tx 20's overflow no-op consumed MAX's
    // whole supply; nothing resurrects it.
    assert_eq!(st.token(&txid(10)).unwrap().circulating(), 0);
    assert_eq!(st.colored_coin(&pt(19, 0)), None);
    assert_eq!(st.balance(&spk(DAVE), &txid(10)), 0);
    // SMALL was burned by the over-assignment no-op of tx 14.
    assert_eq!(st.token(&txid(9)).unwrap().circulating(), 0);
}

#[test]
fn token_blind_control_sees_nothing_and_chain_data_is_never_touched() {
    let (chain, _) = adversarial_chain();
    let blind = strip_payloads(&chain);

    // A token-blind control (payloads stripped) derives ZERO token state
    // from the same value flow — the token layer reads envelopes only.
    let mut st = TokenState::new();
    for h in 0..=blind.tip_height().unwrap() {
        for tx in &blind.block_by_height(h).unwrap().transactions {
            let out = st.apply_tx(h, tx);
            assert_eq!(out.effect, TokenEffect::NoEnvelope);
            assert!(out.burned.is_empty());
        }
    }
    assert!(st.tokens().is_empty());
    assert!(st.colored().is_empty());
    assert!(st.balances().is_empty());

    // And the state machine cannot perturb chain data by construction: it
    // takes `&ChainTx` — BLCH values in equal the same values out.
    let b0 = chain.block_by_height(0).unwrap();
    let values_before: Vec<Vec<u64>> =
        b0.transactions.iter().map(|t| t.outputs.iter().map(|o| o.value).collect()).collect();
    let mut probe = TokenState::new();
    for tx in &b0.transactions {
        probe.apply_tx(0, tx);
    }
    let values_after: Vec<Vec<u64>> =
        b0.transactions.iter().map(|t| t.outputs.iter().map(|o| o.value).collect()).collect();
    assert_eq!(values_before, values_after);
}

#[test]
fn adversarial_stream_is_itself_deterministic() {
    // Hostile traffic must not introduce nondeterminism either.
    let (chain, _) = adversarial_chain();
    let a = synced(&chain);
    let (chain2, _) = adversarial_chain();
    let b = synced(&chain2);
    assert_eq!(a.state(), b.state());
    assert_eq!(a.journal(), b.journal());
    assert_eq!(format!("{:?}", a.state()), format!("{:?}", b.state()));
}

/// Compile-time exhaustiveness guard: adding a `NoOpReason` variant (a new
/// state-level malformed class) breaks this match until the adversarial
/// stream above is extended to cover it.
#[allow(dead_code)]
fn every_noop_reason_is_exercised(r: NoOpReason) {
    match r {
        NoOpReason::MalformedEnvelope => {}      // txs 12, 15, 16, 17
        NoOpReason::TokenIdInUse => {}           // unreachable on a valid chain
        // (txids are unique); the guard is exercised by the duplicate-txid
        // unit test in src/state.rs (a mock feed CAN repeat a txid).
        NoOpReason::IssueRecipientMissing => {}  // txs 18, 22
        NoOpReason::UnknownToken => {}           // tx 13
        NoOpReason::AssignmentOutOfRange => {}   // txs 23, 24
        NoOpReason::OutpointInUse => {}          // unreachable on a valid chain
        // (txids are unique); the replay guard is exercised by the
        // duplicate-txid unit tests in src/state.rs (a mock feed CAN repeat
        // a txid — overwriting an already-colored outpoint must be a no-op).
        NoOpReason::ArithmeticOverflow => {}     // tx 20
        NoOpReason::OverAssignment => {}         // txs 14, 21
    }
}
