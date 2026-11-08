//! End-to-end: the reference indexer driven against a LIVE Bloch node over
//! real JSON-RPC (`getblockcount` / `getblockhash` / `getblockbyheight`).
//!
//! This is `#[ignore]`d and feature-gated so the default, offline test suite
//! stays zero-dependency and hermetic — it only runs when you point it at a
//! node you spawned yourself:
//!
//! ```text
//! # 1. spawn a local zero-value testnet node (mines coinbase to your addr):
//! bloch --testnet --mine --data-dir /tmp/n --rpc-port 16299 --miner-address <addr>
//! # 2. issue + transfer a TKV0 token in ordinary zero-value envelope txs
//! #    (see examples/tkv0_inject.rs in the node repo), then:
//! BLOCH_TKV0_RPC=127.0.0.1:16299 \
//! BLOCH_TKV0_ISSUE_TXID=<hex> \
//! BLOCH_TKV0_RECIPIENT=<20-byte-hex> \
//! BLOCH_TKV0_SUPPLY=21000000 \
//! BLOCH_TKV0_SYMBOL=ACME \
//! BLOCH_TKV0_ISSUER=<20-byte-hex> \
//!   cargo test --features rpc-client --test live_rpc -- --ignored --nocapture
//! ```
//!
//! It asserts the SAME token accounting the offline `MockChain` tests pin,
//! but reconstructed purely from bytes the live node served. Zero consensus
//! change: every call is a public read. One indexer among many; unaudited.

#![cfg(feature = "rpc-client")]

use bloch_tokens::{BlockSource, Indexer, RpcBlockSource};

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex: {s:?}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hex32(s: &str) -> [u8; 32] {
    <[u8; 32]>::try_from(hex_decode(s).as_slice()).expect("32-byte hex")
}

/// Read an env var or skip the test loudly (so an accidental `--ignored` run
/// without setup is obvious, not a false pass).
fn env_or_skip(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => {
            eprintln!("SKIP live_rpc: set {key} (and the other BLOCH_TKV0_* vars)");
            None
        }
    }
}

#[test]
#[ignore = "requires a live local testnet node with a TKV0 issue+transfer; see module docs"]
fn indexer_reconstructs_token_state_from_live_node() {
    let (endpoint, issue_txid_hex, recipient_hex, supply) = match (
        env_or_skip("BLOCH_TKV0_RPC"),
        env_or_skip("BLOCH_TKV0_ISSUE_TXID"),
        env_or_skip("BLOCH_TKV0_RECIPIENT"),
        env_or_skip("BLOCH_TKV0_SUPPLY"),
    ) {
        (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d.parse::<u64>().expect("supply u64")),
        _ => return, // env not set → skip
    };
    let token_id = hex32(&issue_txid_hex);
    let recipient = hex_decode(&recipient_hex);

    let src = RpcBlockSource::new(&endpoint).expect("valid endpoint");

    // ── getblockcount: live tip ──────────────────────────────────────────────
    let tip = src.tip_height().expect("getblockcount over live RPC");
    eprintln!("live tip height = {tip}");
    assert!(tip > 0, "node has mined blocks");

    // ── getblockhash + getblockbyheight round-trip at a real height ──────────
    // The hash the node reports for height 0 must equal the block it serves.
    let h0 = src.block_hash(0).expect("getblockhash(0)");
    let b0 = src.block_by_height(0).expect("getblockbyheight(0)");
    assert_eq!(h0, b0.hash, "getblockhash and getblockbyheight agree at height 0");
    assert_eq!(b0.height, 0);
    // A height past the tip is the node's method-level not-found → HeightNotFound.
    assert!(matches!(
        src.block_by_height(tip + 10_000),
        Err(bloch_tokens::SourceError::HeightNotFound(_))
    ));

    // ── Full replay over live RPC ────────────────────────────────────────────
    let mut ix = Indexer::new();
    let report = ix.sync(&src).expect("indexer sync over live RPC");
    eprintln!(
        "sync: applied {} blocks up to tip {:?} (reorged={})",
        report.applied, report.tip, report.reorged
    );
    assert!(!report.reorged, "fresh indexer never reorgs on first sync");
    assert!(report.applied >= 1);

    // ── The newly-issued token is reconstructed from chain bytes alone ──────
    let info = ix
        .state()
        .token(&token_id)
        .unwrap_or_else(|| panic!("issued token {issue_txid_hex} not found in reconstructed state"));
    eprintln!(
        "token {}: symbol={} decimals={} supply={} burned={} mint_closed={}",
        &issue_txid_hex[..16],
        info.symbol,
        info.decimals,
        info.supply,
        info.burned,
        info.mint_closed
    );
    assert_eq!(info.supply, supply, "reconstructed supply matches the ISSUE envelope");
    assert!(info.mint_closed, "v0 tokens are mint-closed");
    if let Some(sym) = std::env::var("BLOCH_TKV0_SYMBOL").ok().filter(|s| !s.is_empty()) {
        assert_eq!(info.symbol, sym, "reconstructed symbol matches the ISSUE envelope");
    }

    // ── The TRANSFER moved the whole supply to the recipient ────────────────
    let recv_bal = ix.state().balance(&recipient, &token_id);
    assert_eq!(recv_bal, supply, "recipient holds the transferred supply");
    // Nothing was implicitly burned (the transfer assigned the full supply).
    assert_eq!(info.circulating(), supply);

    // Issuer no longer holds any of it (spent the colored output in the transfer).
    if let Some(issuer_hex) = std::env::var("BLOCH_TKV0_ISSUER").ok().filter(|s| !s.is_empty()) {
        let issuer = hex_decode(&issuer_hex);
        assert_eq!(
            ix.state().balance(&issuer, &token_id),
            0,
            "issuer transferred everything away"
        );
    }

    // ── Second sync exercises getblockhash live (fork-point check) and is a
    //    no-op on token facts: the malformed-envelope tx never invalidated its
    //    carrying tx, and re-reading the chain converges to the same state. ──
    let before = ix.state().clone();
    let report2 = ix.sync(&src).expect("second sync over live RPC");
    eprintln!("second sync: applied {} (new blocks since first sync)", report2.applied);
    // The malformed tx (and any later coinbases) are valid chain txs that add
    // no token effect: the token accounting for our token is unchanged.
    assert_eq!(ix.state().token(&token_id).unwrap().supply, supply);
    assert_eq!(ix.state().balance(&recipient, &token_id), supply);
    if report2.applied == 0 {
        assert_eq!(&before, ix.state(), "idempotent when no new blocks arrived");
    }

    eprintln!("LIVE OK: indexer reconstructed the TKV0 token from live JSON-RPC");
}
