//! Deterministic token state machine over TKV0 envelopes.
//!
//! Given the ordered transactions of the selected chain, every independent
//! reader that applies these rules arrives at identical [`TokenState`] — that
//! reproducibility, not consensus, is what makes the standard trustworthy
//! while staying a ZERO consensus change. Nothing here can invalidate a Bloch
//! transaction: a malformed or over-assigning envelope is a **token-layer
//! no-op** and the carrying transaction confirms normally. BLCH values are
//! never read, never modeled, never changed.
//!
//! ## The rules (R1–R6, normative — see `SPEC.md` §3)
//!
//! * **R1 — consumption.** Every spent outpoint that carries color is
//!   consumed: removed from the colored-outpoint set and debited from its
//!   holder's balance. This happens for *every* transaction, envelope or
//!   not, because the base layer destroyed those outputs regardless.
//! * **R2 — no usable envelope ⇒ burn.** If a transaction carries no
//!   envelope (or a malformed one), all color it consumed is burned. An
//!   indexer cannot guess intent.
//! * **R3 — ISSUE.** `token_id := txid` of the issuing transaction, so
//!   registration happens exactly once (a duplicate txid is impossible on a
//!   real chain; the guard also makes any attempted re-issue a no-op — and
//!   since TKV0 mandates the mint-closed flag, *every* v0 token is
//!   mint-closed: re-issuing on it is always a no-op). The full supply is
//!   assigned to **output 0**, which must exist and must not be the envelope
//!   output. An ISSUE never forwards color: color its inputs carried burns.
//! * **R4 — TRANSFER.** Color consumed from the spent outpoints is
//!   re-assigned to this transaction's own outputs per the envelope's
//!   explicit `(vout, amount)` list. Over-assignment (list total exceeds the
//!   color consumed for that token) makes the **whole envelope a token-layer
//!   no-op** — and, per R1+R2, the consumed color burns. Unassigned
//!   remainder burns (no implicit change). Color of *other* tokens consumed
//!   by the same transaction burns (one envelope, one token).
//! * **R5 — checked arithmetic.** Every envelope-influenced sum is
//!   `checked_*`; overflow is a no-op, never a wrap. Internal invariants
//!   (balances mirror colored coins, burned ≤ minted) use `checked_*` +
//!   `expect` so a logic bug fails loudly instead of corrupting state.
//! * **R6 — determinism.** [`TokenState::apply_tx`] is pure: its result
//!   depends only on current state, `height`, and the transaction. Every
//!   container is a `BTreeMap`/`BTreeSet` (never a `HashMap`), so no
//!   observable output — iteration order, `Debug` output, the
//!   [`ApplyOutcome::burned`] ordering — depends on hash randomization.

use std::collections::BTreeMap;

use crate::chain::{ChainTx, OutPoint};
use crate::envelope::{decode_envelope_output, TokenOp, ENVELOPE_MAGIC, FLAG_MINT_CLOSED};

/// A token is identified by the txid of its issuing transaction (32 bytes).
pub type TokenId = [u8; 32];
/// Opaque script bytes (`script_pubkey` in the node's openapi.yaml).
pub type ScriptPubkey = Vec<u8>;

/// Registry entry for one token (metadata immutable after issuance).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenInfo {
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
    /// From the issue flags. TKV0 mandates it, so always `true` in v0.
    pub mint_closed: bool,
    /// Total minted at issuance (fixed in v0 — no re-issue can change it).
    pub supply: u64,
    /// Total ever burned (R2 burns + unassigned remainders).
    pub burned: u64,
    /// Height of the block containing the issuing transaction.
    pub issued_height: u64,
}

impl TokenInfo {
    /// Circulating supply. Invariant: `burned <= supply`.
    pub fn circulating(&self) -> u64 {
        self.supply
            .checked_sub(self.burned)
            .expect("invariant: burned never exceeds supply")
    }
}

/// A colored (token-carrying) unspent output.
///
/// The spec's essential mapping is `(txid, vout) -> (token_id, amount)`; the
/// script is carried alongside so consumption can debit the right balance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColoredCoin {
    pub token_id: TokenId,
    pub amount: u64,
    pub script_pubkey: ScriptPubkey,
}

/// Why an envelope was a token-layer no-op. The carrying Bloch transaction
/// is of course still valid — R1 consumption already happened either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoOpReason {
    /// The first magic-bearing output failed strict decode (or rides a
    /// non-zero-value output).
    MalformedEnvelope,
    /// ISSUE whose txid already names a token. Impossible on a real chain
    /// (duplicate txid); also what any attempted "re-issue" of a mint-closed
    /// v0 token degenerates to — a no-op either way.
    TokenIdInUse,
    /// ISSUE with no output 0, or output 0 is the envelope itself (color
    /// cannot ride the unspendable data output).
    IssueRecipientMissing,
    /// TRANSFER of a token_id that was never issued.
    UnknownToken,
    /// TRANSFER assignment targeting a missing vout or the envelope output.
    AssignmentOutOfRange,
    /// The envelope would credit an outpoint that is ALREADY colored — a
    /// replayed / duplicate-txid transaction. Impossible on a real chain
    /// (txids are unique, same honesty as [`NoOpReason::TokenIdInUse`]); a
    /// mock or hostile feed CAN repeat a txid, and without this guard the
    /// replay would silently overwrite the existing colored coin while its
    /// old balance stayed credited — balances would stop mirroring colored
    /// coins.
    OutpointInUse,
    /// TRANSFER assignment amounts overflow u64 when summed (R5).
    ArithmeticOverflow,
    /// TRANSFER assignment total exceeds the color consumed for that token.
    OverAssignment,
}

/// What a transaction did at the token layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenEffect {
    /// No output carries the envelope magic: an ordinary transaction. Any
    /// color it consumed is in [`ApplyOutcome::burned`] (R2).
    NoEnvelope,
    /// New token registered; full supply assigned to output 0.
    Issued { token_id: TokenId, supply: u64 },
    /// Color re-assigned per the envelope's `(vout, amount)` list.
    /// `assigned` is the list total; any remainder is in `burned`.
    Transferred { token_id: TokenId, assigned: u64 },
    /// Envelope present but a token-layer no-op; consumed color burned.
    NoOp(NoOpReason),
}

/// Result of applying one transaction. `burned` is per token, ascending
/// token id (BTreeMap order — deterministic).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyOutcome {
    pub effect: TokenEffect,
    pub burned: Vec<(TokenId, u64)>,
}

/// The full derived token state. Every map is a `BTreeMap` so comparison,
/// iteration and `Debug` output are canonical on every machine (R6).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TokenState {
    /// Token registry, keyed by token id (= issuing txid).
    tokens: BTreeMap<TokenId, TokenInfo>,
    /// Colored-outpoint map: which UTXOs currently carry which color.
    colored: BTreeMap<OutPoint, ColoredCoin>,
    /// Balances: script_pubkey -> token id -> amount. Zero entries are
    /// pruned eagerly so state equality is exact.
    balances: BTreeMap<ScriptPubkey, BTreeMap<TokenId, u64>>,
}

impl TokenState {
    pub fn new() -> Self {
        Self::default()
    }

    /// The token registry (read-only).
    pub fn tokens(&self) -> &BTreeMap<TokenId, TokenInfo> {
        &self.tokens
    }

    pub fn token(&self, id: &TokenId) -> Option<&TokenInfo> {
        self.tokens.get(id)
    }

    /// The colored-outpoint map (read-only).
    pub fn colored(&self) -> &BTreeMap<OutPoint, ColoredCoin> {
        &self.colored
    }

    pub fn colored_coin(&self, outpoint: &OutPoint) -> Option<&ColoredCoin> {
        self.colored.get(outpoint)
    }

    /// Balance of `script_pubkey` in token `id` (0 when absent).
    pub fn balance(&self, script_pubkey: &[u8], id: &TokenId) -> u64 {
        self.balances
            .get(script_pubkey)
            .and_then(|per| per.get(id))
            .copied()
            .unwrap_or(0)
    }

    /// All token balances of one script (`None` when it holds nothing).
    pub fn balances_of(&self, script_pubkey: &[u8]) -> Option<&BTreeMap<TokenId, u64>> {
        self.balances.get(script_pubkey)
    }

    /// All balances (read-only view).
    pub fn balances(&self) -> &BTreeMap<ScriptPubkey, BTreeMap<TokenId, u64>> {
        &self.balances
    }

    /// Apply one already-confirmed transaction, in block order. Pure and
    /// deterministic (R6); total — never panics on any input, never returns
    /// an error (the token layer cannot invalidate a chain transaction).
    pub fn apply_tx(&mut self, height: u64, tx: &ChainTx) -> ApplyOutcome {
        // ── R1: consume color from every spent outpoint ───────────────────
        // `burn` starts as "everything consumed burns" (R2); the valid
        // branches below subtract what they legitimately re-assign.
        let mut burn: BTreeMap<TokenId, u64> = BTreeMap::new();
        for outpoint in &tx.inputs {
            if let Some(coin) = self.colored.remove(outpoint) {
                let entry = burn.entry(coin.token_id).or_insert(0);
                *entry = entry
                    .checked_add(coin.amount)
                    .expect("invariant: consumed color bounded by token supply (u64)");
                self.debit_balance(&coin.script_pubkey, &coin.token_id, coin.amount);
            }
        }

        // ── First envelope wins (same rule as envelope::extract_envelope,
        //    via the same decode_envelope_output helper) ────────────────────
        let candidate = tx
            .outputs
            .iter()
            .enumerate()
            .find(|(_, o)| o.script_pubkey.starts_with(&ENVELOPE_MAGIC));

        let effect = match candidate {
            None => TokenEffect::NoEnvelope,
            Some((env_idx, out)) => match decode_envelope_output(out) {
                Err(_) => TokenEffect::NoOp(NoOpReason::MalformedEnvelope),
                Ok(op) => self.execute(height, tx, env_idx, op, &mut burn),
            },
        };

        // ── Burn bookkeeping (ascending token id — deterministic) ─────────
        let mut burned = Vec::with_capacity(burn.len());
        for (token_id, amount) in burn {
            if amount == 0 {
                continue;
            }
            if let Some(info) = self.tokens.get_mut(&token_id) {
                info.burned = info
                    .burned
                    .checked_add(amount)
                    .expect("invariant: burned bounded by supply (u64)");
            }
            burned.push((token_id, amount));
        }
        ApplyOutcome { effect, burned }
    }

    /// Execute a decoded envelope. `burn` holds the color consumed by R1;
    /// a valid TRANSFER removes from it what it re-assigns.
    fn execute(
        &mut self,
        height: u64,
        tx: &ChainTx,
        env_idx: usize,
        op: TokenOp,
        burn: &mut BTreeMap<TokenId, u64>,
    ) -> TokenEffect {
        match op {
            // ── R3: ISSUE ─────────────────────────────────────────────────
            TokenOp::Issue { decimals, flags, supply, symbol, name } => {
                let token_id: TokenId = tx.txid;
                if self.tokens.contains_key(&token_id) {
                    return TokenEffect::NoOp(NoOpReason::TokenIdInUse);
                }
                // Supply goes to output 0, which must exist and must not be
                // the (unspendable) envelope output itself.
                if env_idx == 0 || tx.outputs.is_empty() {
                    return TokenEffect::NoOp(NoOpReason::IssueRecipientMissing);
                }
                // Replay guard: never overwrite an already-colored outpoint
                // (a duplicate-txid feed — see NoOpReason::OutpointInUse).
                if self.colored.contains_key(&OutPoint { txid: tx.txid, vout: 0 }) {
                    return TokenEffect::NoOp(NoOpReason::OutpointInUse);
                }
                self.tokens.insert(
                    token_id,
                    TokenInfo {
                        symbol,
                        name,
                        decimals,
                        mint_closed: flags & FLAG_MINT_CLOSED != 0,
                        supply,
                        burned: 0,
                        issued_height: height,
                    },
                );
                self.credit(
                    OutPoint { txid: tx.txid, vout: 0 },
                    token_id,
                    supply,
                    &tx.outputs[0].script_pubkey,
                );
                // Note: any color consumed by this tx stays in `burn` — an
                // ISSUE never forwards color.
                TokenEffect::Issued { token_id, supply }
            }

            // ── R4: TRANSFER ──────────────────────────────────────────────
            TokenOp::Transfer { token_id, assignments } => {
                if !self.tokens.contains_key(&token_id) {
                    return TokenEffect::NoOp(NoOpReason::UnknownToken);
                }
                // Wire decode already guarantees: 1..=MAX_ASSIGNMENTS
                // entries, no duplicate vout, every amount >= 1. Still to
                // check against *this* transaction: vout range, not the
                // envelope output, and the checked total (R5).
                let mut assigned: u64 = 0;
                for (vout, amount) in &assignments {
                    if *vout as usize >= tx.outputs.len() || *vout as usize == env_idx {
                        return TokenEffect::NoOp(NoOpReason::AssignmentOutOfRange);
                    }
                    // Replay guard: crediting `(txid, vout)` must never
                    // overwrite an existing colored coin at that outpoint —
                    // only a replayed / duplicate-txid transaction can get
                    // here (see NoOpReason::OutpointInUse). Checked BEFORE
                    // any credit so the whole envelope is a no-op.
                    if self.colored.contains_key(&OutPoint { txid: tx.txid, vout: *vout }) {
                        return TokenEffect::NoOp(NoOpReason::OutpointInUse);
                    }
                    match assigned.checked_add(*amount) {
                        Some(sum) => assigned = sum,
                        None => return TokenEffect::NoOp(NoOpReason::ArithmeticOverflow),
                    }
                }
                let available = burn.get(&token_id).copied().unwrap_or(0);
                if assigned > available {
                    // R4: over-assignment ⇒ whole envelope no-op (consumed
                    // color still burns — the outpoints are gone either way).
                    return TokenEffect::NoOp(NoOpReason::OverAssignment);
                }
                // Valid: re-assign; only the remainder (if any) burns.
                let remainder = available - assigned; // covered by the guard
                if remainder == 0 {
                    burn.remove(&token_id);
                } else {
                    burn.insert(token_id, remainder);
                }
                for (vout, amount) in assignments {
                    self.credit(
                        OutPoint { txid: tx.txid, vout },
                        token_id,
                        amount,
                        &tx.outputs[vout as usize].script_pubkey,
                    );
                }
                TokenEffect::Transferred { token_id, assigned }
            }
        }
    }

    /// Record a colored output and credit its script's balance.
    fn credit(&mut self, outpoint: OutPoint, token_id: TokenId, amount: u64, script: &[u8]) {
        debug_assert!(amount > 0, "wire decode guarantees non-zero amounts");
        self.colored.insert(
            outpoint,
            ColoredCoin { token_id, amount, script_pubkey: script.to_vec() },
        );
        let entry = self
            .balances
            .entry(script.to_vec())
            .or_default()
            .entry(token_id)
            .or_insert(0);
        *entry = entry
            .checked_add(amount)
            .expect("invariant: balance bounded by token supply (u64)");
    }

    /// Debit a balance, pruning zero entries so state equality is exact.
    fn debit_balance(&mut self, script: &[u8], token_id: &TokenId, amount: u64) {
        let per = self
            .balances
            .get_mut(script)
            .expect("invariant: colored coin implies a balance entry for its script");
        let bal = per
            .get_mut(token_id)
            .expect("invariant: colored coin implies a balance entry for its token");
        *bal = bal
            .checked_sub(amount)
            .expect("invariant: balance covers every colored coin debited from it");
        if *bal == 0 {
            per.remove(token_id);
        }
        if per.is_empty() {
            self.balances.remove(script);
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{TokenOp, TxOut, FLAG_MINT_CLOSED};

    fn txid(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn spk(n: u8) -> Vec<u8> {
        vec![n; 20]
    }

    fn pay(script: Vec<u8>) -> TxOut {
        TxOut { value: 546, script_pubkey: script }
    }

    fn env_out(op: &TokenOp) -> TxOut {
        TxOut { value: 0, script_pubkey: op.encode() }
    }

    fn issue_op(supply: u64) -> TokenOp {
        TokenOp::Issue {
            decimals: 8,
            flags: FLAG_MINT_CLOSED,
            supply,
            symbol: "TOK".into(),
            name: "Token".into(),
        }
    }

    /// Issue tx: outputs[0] = recipient (gets full supply), [1] = envelope.
    fn issue_tx(n: u8, to: Vec<u8>, supply: u64) -> ChainTx {
        ChainTx {
            txid: txid(n),
            inputs: vec![],
            outputs: vec![pay(to), env_out(&issue_op(supply))],
        }
    }

    /// Transfer tx: `recipients` scripts become outputs 0..; envelope last.
    fn transfer_tx(
        n: u8,
        spend: Vec<OutPoint>,
        token: TokenId,
        assignments: Vec<(u32, u64)>,
        recipients: Vec<Vec<u8>>,
    ) -> ChainTx {
        let mut outputs: Vec<TxOut> = recipients.into_iter().map(pay).collect();
        outputs.push(env_out(&TokenOp::Transfer { token_id: token, assignments }));
        ChainTx { txid: txid(n), inputs: spend, outputs }
    }

    fn op(t: u8, vout: u32) -> OutPoint {
        OutPoint { txid: txid(t), vout }
    }

    #[test]
    fn issue_assigns_full_supply_to_output_zero() {
        let mut st = TokenState::new();
        let out = st.apply_tx(10, &issue_tx(1, spk(0xA1), 1_000_000));
        assert_eq!(out.effect, TokenEffect::Issued { token_id: txid(1), supply: 1_000_000 });
        assert!(out.burned.is_empty());

        let info = st.token(&txid(1)).unwrap();
        assert_eq!(info.supply, 1_000_000);
        assert_eq!(info.symbol, "TOK");
        assert!(info.mint_closed, "TKV0 tokens are always mint-closed");
        assert_eq!(info.issued_height, 10);
        assert_eq!(info.circulating(), 1_000_000);
        assert_eq!(
            st.colored_coin(&op(1, 0)).map(|c| (c.token_id, c.amount)),
            Some((txid(1), 1_000_000))
        );
        assert_eq!(st.balance(&spk(0xA1), &txid(1)), 1_000_000);
    }

    #[test]
    fn issue_with_envelope_at_output_zero_is_noop() {
        let mut st = TokenState::new();
        let tx = ChainTx {
            txid: txid(1),
            inputs: vec![],
            outputs: vec![env_out(&issue_op(5)), pay(spk(0xA1))],
        };
        let out = st.apply_tx(0, &tx);
        assert_eq!(out.effect, TokenEffect::NoOp(NoOpReason::IssueRecipientMissing));
        assert!(st.tokens().is_empty());
        assert!(st.colored().is_empty());
        assert!(st.balances().is_empty());
    }

    #[test]
    fn duplicate_issue_txid_is_noop_and_covers_reissue() {
        // Impossible on a real chain (duplicate txid); the guard also makes
        // any attempted re-issue of the (mint-closed) token a no-op.
        let mut st = TokenState::new();
        st.apply_tx(0, &issue_tx(1, spk(0xA1), 10));
        let out = st.apply_tx(1, &issue_tx(1, spk(0xB2), 99));
        assert_eq!(out.effect, TokenEffect::NoOp(NoOpReason::TokenIdInUse));
        assert_eq!(st.token(&txid(1)).unwrap().supply, 10);
        assert!(st.token(&txid(1)).unwrap().mint_closed);
        assert_eq!(st.balance(&spk(0xB2), &txid(1)), 0);
    }

    #[test]
    fn transfer_moves_color_and_burns_unassigned_remainder() {
        let mut st = TokenState::new();
        let token = txid(1);
        st.apply_tx(0, &issue_tx(1, spk(0xA1), 100));

        // Assign 60 to vout0 (bob) and 30 to vout1 (alice change);
        // 10 unassigned => burned (no implicit change).
        let t = transfer_tx(
            2,
            vec![op(1, 0)],
            token,
            vec![(0, 60), (1, 30)],
            vec![spk(0xB2), spk(0xA1)],
        );
        let out = st.apply_tx(1, &t);
        assert_eq!(out.effect, TokenEffect::Transferred { token_id: token, assigned: 90 });
        assert_eq!(out.burned, vec![(token, 10)]);

        assert_eq!(st.colored_coin(&op(1, 0)), None, "consumed");
        assert_eq!(st.balance(&spk(0xB2), &token), 60);
        assert_eq!(st.balance(&spk(0xA1), &token), 30);
        assert_eq!(st.token(&token).unwrap().burned, 10);
        assert_eq!(st.token(&token).unwrap().circulating(), 90);
    }

    #[test]
    fn over_assignment_is_whole_envelope_noop_and_burns() {
        let mut st = TokenState::new();
        let token = txid(1);
        st.apply_tx(0, &issue_tx(1, spk(0xA1), 100));

        let t = transfer_tx(2, vec![op(1, 0)], token, vec![(0, 101)], vec![spk(0xB2)]);
        let out = st.apply_tx(1, &t);
        assert_eq!(out.effect, TokenEffect::NoOp(NoOpReason::OverAssignment));
        // R1+R2: the spent color still burns — nobody receives anything.
        assert_eq!(out.burned, vec![(token, 100)]);
        assert_eq!(st.balance(&spk(0xA1), &token), 0);
        assert_eq!(st.balance(&spk(0xB2), &token), 0);
        assert_eq!(st.token(&token).unwrap().circulating(), 0);
    }

    #[test]
    fn spend_without_envelope_burns_color() {
        let mut st = TokenState::new();
        let token = txid(1);
        st.apply_tx(0, &issue_tx(1, spk(0xA1), 100));

        let plain = ChainTx {
            txid: txid(2),
            inputs: vec![op(1, 0)],
            outputs: vec![pay(spk(0xB2))],
        };
        let out = st.apply_tx(1, &plain);
        assert_eq!(out.effect, TokenEffect::NoEnvelope);
        assert_eq!(out.burned, vec![(token, 100)]);
        assert_eq!(st.token(&token).unwrap().circulating(), 0);
        assert!(st.balances().is_empty(), "zero entries pruned");
    }

    #[test]
    fn malformed_envelope_burns_color() {
        let mut st = TokenState::new();
        let token = txid(1);
        st.apply_tx(0, &issue_tx(1, spk(0xA1), 100));

        // Magic-bearing but truncated payload: strict decode fails.
        let mut bad = issue_op(5).encode();
        bad.truncate(bad.len() - 1);
        let t = ChainTx {
            txid: txid(2),
            inputs: vec![op(1, 0)],
            outputs: vec![pay(spk(0xB2)), TxOut { value: 0, script_pubkey: bad }],
        };
        let out = st.apply_tx(1, &t);
        assert_eq!(out.effect, TokenEffect::NoOp(NoOpReason::MalformedEnvelope));
        assert_eq!(out.burned, vec![(token, 100)]);
    }

    #[test]
    fn transfer_of_unknown_token_is_noop_and_burns_consumed() {
        let mut st = TokenState::new();
        let token = txid(1);
        st.apply_tx(0, &issue_tx(1, spk(0xA1), 5));
        // Envelope names a never-issued token while spending real color.
        let t = transfer_tx(2, vec![op(1, 0)], txid(9), vec![(0, 5)], vec![spk(0xB2)]);
        let out = st.apply_tx(1, &t);
        assert_eq!(out.effect, TokenEffect::NoOp(NoOpReason::UnknownToken));
        assert_eq!(out.burned, vec![(token, 5)]);
        assert!(st.colored().is_empty());
    }

    #[test]
    fn assignment_to_missing_or_envelope_vout_is_noop() {
        let mut st = TokenState::new();
        let token = txid(1);
        st.apply_tx(0, &issue_tx(1, spk(0xA1), 100));

        // vout 5 does not exist (outputs: recipient at 0, envelope at 1).
        let t = transfer_tx(2, vec![op(1, 0)], token, vec![(5, 10)], vec![spk(0xB2)]);
        let out = st.apply_tx(1, &t);
        assert_eq!(out.effect, TokenEffect::NoOp(NoOpReason::AssignmentOutOfRange));
        assert_eq!(out.burned, vec![(token, 100)]);

        // Fresh token; try to color the envelope output itself (index 1).
        st.apply_tx(2, &issue_tx(3, spk(0xA1), 50));
        let t = transfer_tx(4, vec![op(3, 0)], txid(3), vec![(1, 10)], vec![spk(0xB2)]);
        let out = st.apply_tx(3, &t);
        assert_eq!(out.effect, TokenEffect::NoOp(NoOpReason::AssignmentOutOfRange));
        assert_eq!(st.token(&txid(3)).unwrap().circulating(), 0);
    }

    #[test]
    fn assignment_sum_overflow_is_noop_not_wrap() {
        let mut st = TokenState::new();
        let token = txid(1);
        st.apply_tx(0, &issue_tx(1, spk(0xA1), u64::MAX));
        let t = transfer_tx(
            2,
            vec![op(1, 0)],
            token,
            vec![(0, u64::MAX), (1, 1)],
            vec![spk(0xB2), spk(0xC3)],
        );
        let out = st.apply_tx(1, &t);
        assert_eq!(out.effect, TokenEffect::NoOp(NoOpReason::ArithmeticOverflow));
        assert_eq!(st.token(&token).unwrap().circulating(), 0); // burned
    }

    /// Regression (replay guard): a duplicate-txid TRANSFER — impossible on a
    /// real chain, but a mock/hostile feed CAN repeat a txid — used to
    /// silently OVERWRITE the colored coin at `(txid, vout)` while the old
    /// coin's balance stayed credited, so balances stopped mirroring colored
    /// coins. It must be a whole-envelope no-op instead.
    #[test]
    fn duplicate_txid_transfer_cannot_overwrite_colored_outpoint() {
        let mut st = TokenState::new();
        let token_a = txid(1);
        let token_b = txid(8);
        st.apply_tx(0, &issue_tx(1, spk(0xA1), 100)); // token A → alice at (1,0)
        st.apply_tx(0, &issue_tx(8, spk(0xA1), 40)); // token B → alice at (8,0)

        // Legitimate transfer: token A moves to bob at outpoint (2,0).
        let t1 = transfer_tx(2, vec![op(1, 0)], token_a, vec![(0, 100)], vec![spk(0xB2)]);
        st.apply_tx(1, &t1);
        assert_eq!(st.balance(&spk(0xB2), &token_a), 100);

        // REPLAYED txid 2: a different transfer (token B → carol) whose
        // credit would land on the already-colored outpoint (2,0).
        let replay = transfer_tx(2, vec![op(8, 0)], token_b, vec![(0, 40)], vec![spk(0xC3)]);
        let out = st.apply_tx(2, &replay);
        assert_eq!(out.effect, TokenEffect::NoOp(NoOpReason::OutpointInUse));
        // R1+R2 unchanged: the color it consumed still burns.
        assert_eq!(out.burned, vec![(token_b, 40)]);

        // The original colored coin and its balance survive untouched…
        assert_eq!(
            st.colored_coin(&op(2, 0)).map(|c| (c.token_id, c.amount)),
            Some((token_a, 100)),
            "the replay must not overwrite the existing colored outpoint"
        );
        assert_eq!(st.balance(&spk(0xB2), &token_a), 100);
        // …and the replay credited nobody.
        assert_eq!(st.balance(&spk(0xC3), &token_b), 0);
    }

    /// Same replay guard, ISSUE side: an ISSUE whose txid collides with an
    /// outpoint some earlier (duplicate-txid) transaction already colored
    /// must not overwrite it.
    #[test]
    fn duplicate_txid_issue_cannot_overwrite_colored_outpoint() {
        let mut st = TokenState::new();
        let token_a = txid(1);
        st.apply_tx(0, &issue_tx(1, spk(0xA1), 100));
        // Transfer with txid 3 colors outpoint (3,0) with token A.
        let t = transfer_tx(3, vec![op(1, 0)], token_a, vec![(0, 100)], vec![spk(0xB2)]);
        st.apply_tx(1, &t);
        assert!(st.colored_coin(&op(3, 0)).is_some());

        // A later ISSUE reusing txid 3 would credit (3,0) — refuse it.
        let out = st.apply_tx(2, &issue_tx(3, spk(0xC3), 7));
        assert_eq!(out.effect, TokenEffect::NoOp(NoOpReason::OutpointInUse));
        assert_eq!(st.token(&txid(3)), None, "the colliding issue must register nothing");
        assert_eq!(
            st.colored_coin(&op(3, 0)).map(|c| (c.token_id, c.amount)),
            Some((token_a, 100))
        );
    }

    #[test]
    fn issue_never_forwards_color() {
        let mut st = TokenState::new();
        st.apply_tx(0, &issue_tx(1, spk(0xA1), 7));
        // A new ISSUE that also spends the old colored coin: old color burns.
        let tx = ChainTx {
            txid: txid(2),
            inputs: vec![op(1, 0)],
            outputs: vec![pay(spk(0xB2)), env_out(&issue_op(3))],
        };
        let out = st.apply_tx(1, &tx);
        assert_eq!(out.effect, TokenEffect::Issued { token_id: txid(2), supply: 3 });
        assert_eq!(out.burned, vec![(txid(1), 7)]);
        assert_eq!(st.token(&txid(1)).unwrap().circulating(), 0);
        assert_eq!(st.balance(&spk(0xB2), &txid(2)), 3);
    }

    #[test]
    fn one_envelope_one_token_other_color_burns() {
        // A valid transfer of token A that also spends token-B color:
        // B's color burns (one envelope, one token).
        let mut st = TokenState::new();
        st.apply_tx(0, &issue_tx(1, spk(0xA1), 100)); // token A
        st.apply_tx(0, &issue_tx(2, spk(0xA1), 40)); // token B
        let t = transfer_tx(
            3,
            vec![op(1, 0), op(2, 0)],
            txid(1),
            vec![(0, 100)],
            vec![spk(0xB2)],
        );
        let out = st.apply_tx(1, &t);
        assert_eq!(out.effect, TokenEffect::Transferred { token_id: txid(1), assigned: 100 });
        assert_eq!(out.burned, vec![(txid(2), 40)]);
        assert_eq!(st.balance(&spk(0xB2), &txid(1)), 100);
        assert_eq!(st.token(&txid(2)).unwrap().circulating(), 0);
    }

    #[test]
    fn blch_values_are_never_touched() {
        // The state machine takes &ChainTx and colors ride outpoints, not
        // values: after a full flow the BLCH `value` fields are untouched,
        // and no implicit base-coin token ever exists.
        let issue = issue_tx(1, spk(0xA1), 100);
        let before: Vec<u64> = issue.outputs.iter().map(|o| o.value).collect();
        let mut st = TokenState::new();
        st.apply_tx(0, &issue);
        let after: Vec<u64> = issue.outputs.iter().map(|o| o.value).collect();
        assert_eq!(before, after);
        assert_eq!(st.tokens().len(), 1, "only the explicit ISSUE created a token");
    }

    #[test]
    fn equal_replays_yield_identical_state_and_debug() {
        let run = || {
            let mut st = TokenState::new();
            let mut outcomes = Vec::new();
            outcomes.push(st.apply_tx(0, &issue_tx(1, spk(0xA1), 1000)));
            outcomes.push(st.apply_tx(0, &issue_tx(2, spk(0xB2), 500)));
            outcomes.push(st.apply_tx(
                1,
                &transfer_tx(
                    3,
                    vec![op(1, 0)],
                    txid(1),
                    vec![(0, 400), (1, 600)],
                    vec![spk(0xB2), spk(0xA1)],
                ),
            ));
            outcomes.push(st.apply_tx(
                2,
                &transfer_tx(4, vec![op(2, 0)], txid(2), vec![(0, 500)], vec![spk(0xC3)]),
            ));
            (st, outcomes)
        };
        let (a, oa) = run();
        let (b, ob) = run();
        assert_eq!(a, b, "two independent replays, identical state");
        assert_eq!(oa, ob, "identical outcomes too");
        // BTreeMap-backed Debug output is order-stable — no hash-order leak
        // in any observable output.
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
    }
}
