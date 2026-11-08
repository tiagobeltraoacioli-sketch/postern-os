// SPDX-License-Identifier: MIT OR Apache-2.0
//! Swap / DEX backend — the Postern Desktop "Swap" pane's Tauri commands
//! (mirrors ../src/modules/swap.js exactly).
//!
//! What is REAL here (and unit-tested below):
//!   * `swap_quote` — the PosternDex (Uniswap-v2-model) constant-product
//!     `x*y=k` quote: `getAmountOut` with the pool fee, price impact, and the
//!     slippage-adjusted minimum-received. Exact integer math over `U256`
//!     (18-dp wei), byte-for-byte the same rounding Uniswap v2's Router uses.
//!   * `swap_build_tx` — the EVM calldata a wallet would submit: an ERC-20
//!     `approve` + `swapExactTokensForTokens` for a swap, or the WBLCH
//!     `deposit()` / `withdraw()` for the 1:1 bridge on-ramp. Real 4-byte
//!     selectors (keccak256 of the signature) + real ABI head/tail encoding.
//!
//! What is PREVIEW (never faked):
//!   * `swap_l2_probe` — a real JSON-RPC liveness check (`eth_chainId` +
//!     `eth_blockNumber`) against a configured L2 EVM endpoint. There is no
//!     live Bloch L2 today (chain_id 700771 is unregistered; the node / RPC /
//!     prover are stubs), so this HONESTLY reports "not reachable" for any real
//!     endpoint. It never fabricates a chain, a block, or a tx hash. Execution
//!     stays PREVIEW until a live L2 (or a local devnet) exists.
//!
//! HONESTY (carried verbatim in [`HONESTY`], surfaced by the pane): PosternDex
//! and the Bloch EVM L2 are DESIGN-SCAFFOLD, NOT live. WBLCH is a genesis
//! predeploy that has never been deployed; no pools exist; the v1 bridge vault
//! is CUSTODY. Zero-value; BLCH/wBLCH are worthless; unaudited.

use primitive_types::U256;
use serde::Deserialize;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

/// The mandatory honesty string. Every command response carries it so a caller
/// can never present the quote/build as a live, executed swap.
pub const HONESTY: &str = "PosternDex + the Bloch EVM L2 are DESIGN-SCAFFOLD, NOT live: chain_id 700771 is unregistered, no L2 node/RPC/prover runs, WBLCH is a genesis predeploy never actually deployed, and no pools exist. The constant-product quote math and the EVM calldata are REAL and tested offline; on-chain EXECUTION is PREVIEW until a live L2 (or local devnet) exists. The v1 bridge vault is CUSTODY. Zero-value; BLCH/wBLCH are worthless; unaudited.";

/// Placeholders pinned to `l2/bloch-l2-bridge/deploy/testnet.json`. chain_id
/// 700771 is a placeholder pending ethereum-lists/chains registration; the
/// router address is the *unchanged* Uniswap v2 mainnet artifact address (the
/// L2 deploys it byte-for-byte — that is the point of the EVM L2), still a
/// placeholder until the artifacts are vendored + the activation gates clear.
pub const L2_CHAIN_ID: u64 = 700_771;
pub const WBLCH_PREDEPLOY: &str = "0x4200000000000000000000000000000000000006";
pub const ROUTER02: &str = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D";

// ── core AMM math (REAL, exact integer, U256) ───────────────────────────────

/// Uniswap-v2 `getAmountOut`: given an input amount and the pool reserves,
/// the constant-product output after the pool fee. `fee_bps` is the fee in
/// basis points (30 = 0.30%, the PosternDex default). Fails closed on a zero
/// input or zero liquidity — never returns a made-up number.
pub fn get_amount_out(
    amount_in: U256,
    reserve_in: U256,
    reserve_out: U256,
    fee_bps: u32,
) -> Result<U256, String> {
    if amount_in.is_zero() {
        return Err("INSUFFICIENT_INPUT_AMOUNT: amount-in must be greater than zero".into());
    }
    if reserve_in.is_zero() || reserve_out.is_zero() {
        return Err("INSUFFICIENT_LIQUIDITY: both pool reserves must be greater than zero".into());
    }
    if fee_bps >= 10_000 {
        return Err("fee_bps must be less than 10000 (100%)".into());
    }
    let factor = U256::from(10_000u32 - fee_bps);
    let ten_k = U256::from(10_000u32);
    let amount_in_with_fee = amount_in
        .checked_mul(factor)
        .ok_or("overflow computing amount_in_with_fee")?;
    let numerator = amount_in_with_fee
        .checked_mul(reserve_out)
        .ok_or("overflow computing numerator")?;
    let denominator = reserve_in
        .checked_mul(ten_k)
        .ok_or("overflow computing denominator")?
        .checked_add(amount_in_with_fee)
        .ok_or("overflow computing denominator")?;
    Ok(numerator / denominator)
}

/// Price impact in basis points: how far the execution price is from the
/// pre-trade mid price `reserve_out / reserve_in`. Monotonically increasing in
/// `amount_in`. Returns `10000 - (amount_out * reserve_in * 10000) /
/// (amount_in * reserve_out)`, clamped at 0.
pub fn price_impact_bps(
    amount_in: U256,
    amount_out: U256,
    reserve_in: U256,
    reserve_out: U256,
) -> Result<u64, String> {
    if amount_in.is_zero() || reserve_out.is_zero() {
        return Err("cannot compute price impact with zero input or zero reserve".into());
    }
    let ten_k = U256::from(10_000u32);
    let num = amount_out
        .checked_mul(reserve_in)
        .ok_or("overflow (impact numerator)")?
        .checked_mul(ten_k)
        .ok_or("overflow (impact numerator)")?;
    let den = amount_in
        .checked_mul(reserve_out)
        .ok_or("overflow (impact denominator)")?;
    let ratio_bps = num / den; // (execPrice/midPrice) * 10000, floored
    let impact = if ratio_bps >= ten_k {
        U256::zero()
    } else {
        ten_k - ratio_bps
    };
    Ok(impact.as_u64())
}

/// Slippage floor: the minimum output a swap will accept, `amount_out *
/// (10000 - slippage_bps) / 10000`. This is the `amountOutMin` argument.
pub fn min_received(amount_out: U256, slippage_bps: u32) -> Result<U256, String> {
    if slippage_bps >= 10_000 {
        return Err("slippage_bps must be less than 10000 (100%)".into());
    }
    let keep = U256::from(10_000u32 - slippage_bps);
    Ok(amount_out * keep / U256::from(10_000u32))
}

fn parse_u256_dec(s: &str) -> Result<U256, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err("empty amount".into());
    }
    U256::from_dec_str(t).map_err(|e| format!("invalid decimal integer '{t}': {e}"))
}

// ── EVM ABI calldata (REAL selectors + encoding) ────────────────────────────

fn selector(sig: &str) -> [u8; 4] {
    let mut h = Keccak256::new();
    h.update(sig.as_bytes());
    let d = h.finalize();
    [d[0], d[1], d[2], d[3]]
}

fn enc_u256(v: U256) -> [u8; 32] {
    v.to_big_endian()
}

/// Parse a `0x`-prefixed 20-byte address, left-padded into a 32-byte ABI word.
fn enc_address(addr: &str) -> Result<[u8; 32], String> {
    let h = addr.trim().strip_prefix("0x").unwrap_or(addr.trim());
    if h.len() != 40 {
        return Err(format!("address '{addr}' must be 20 bytes (40 hex chars)"));
    }
    let raw = hex::decode(h).map_err(|e| format!("address '{addr}' is not hex: {e}"))?;
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&raw);
    Ok(w)
}

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// `approve(address spender, uint256 amount)` calldata.
fn build_approve(spender: &str, amount: U256) -> Result<String, String> {
    let mut out = Vec::with_capacity(4 + 64);
    out.extend_from_slice(&selector("approve(address,uint256)"));
    out.extend_from_slice(&enc_address(spender)?);
    out.extend_from_slice(&enc_u256(amount));
    Ok(hex0x(&out))
}

/// `swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin,
/// address[] path, address to, uint256 deadline)` calldata (path = [in, out]).
fn build_swap(
    amount_in: U256,
    amount_out_min: U256,
    token_in: &str,
    token_out: &str,
    to: &str,
    deadline: U256,
) -> Result<String, String> {
    let mut out = Vec::new();
    out.extend_from_slice(&selector(
        "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
    ));
    // head: 5 static-size words (the dynamic array is a 32-byte offset).
    out.extend_from_slice(&enc_u256(amount_in)); // amountIn
    out.extend_from_slice(&enc_u256(amount_out_min)); // amountOutMin
    out.extend_from_slice(&enc_u256(U256::from(160u32))); // offset to path (5*32)
    out.extend_from_slice(&enc_address(to)?); // to
    out.extend_from_slice(&enc_u256(deadline)); // deadline
    // tail: the path array (length + two addresses).
    out.extend_from_slice(&enc_u256(U256::from(2u32)));
    out.extend_from_slice(&enc_address(token_in)?);
    out.extend_from_slice(&enc_address(token_out)?);
    Ok(hex0x(&out))
}

/// WBLCH `deposit()` (wrap native BLCH → wBLCH 1:1) calldata.
fn build_deposit() -> String {
    hex0x(&selector("deposit()"))
}

/// WBLCH `withdraw(uint256 wad)` (unwrap wBLCH → native BLCH 1:1) calldata.
fn build_withdraw(wad: U256) -> Result<String, String> {
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&selector("withdraw(uint256)"));
    out.extend_from_slice(&enc_u256(wad));
    Ok(hex0x(&out))
}

// ── #[tauri::command] surface ───────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuoteArgs {
    pub amount_in: String,
    pub reserve_in: String,
    pub reserve_out: String,
    #[serde(default = "default_fee_bps")]
    pub fee_bps: u32,
    #[serde(default)]
    pub slippage_bps: u32,
}
fn default_fee_bps() -> u32 {
    30
}

/// REAL constant-product quote. Amounts are decimal strings (18-dp wei) so
/// they survive JS `Number` limits. Returns the output, price impact (bps) and
/// the slippage floor — all exact integer math, no rounding tricks.
#[tauri::command]
pub fn swap_quote(args: QuoteArgs) -> Result<Value, String> {
    let amount_in = parse_u256_dec(&args.amount_in)?;
    let reserve_in = parse_u256_dec(&args.reserve_in)?;
    let reserve_out = parse_u256_dec(&args.reserve_out)?;
    let amount_out = get_amount_out(amount_in, reserve_in, reserve_out, args.fee_bps)?;
    let impact = price_impact_bps(amount_in, amount_out, reserve_in, reserve_out)?;
    let min_out = min_received(amount_out, args.slippage_bps)?;
    Ok(json!({
        "amountOut": amount_out.to_string(),
        "minReceived": min_out.to_string(),
        "priceImpactBps": impact,
        "feeBps": args.fee_bps,
        "slippageBps": args.slippage_bps,
        "honesty": HONESTY,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildArgs {
    /// "swap" | "wrap" | "unwrap"
    pub kind: String,
    #[serde(default)]
    pub amount_in: String,
    #[serde(default)]
    pub amount_out_min: String,
    #[serde(default)]
    pub token_in: String,
    #[serde(default)]
    pub token_out: String,
    #[serde(default)]
    pub recipient: String,
    #[serde(default)]
    pub deadline: String,
    #[serde(default)]
    pub router: String,
}

/// REAL EVM calldata builder. Returns the ordered transaction step(s) a wallet
/// would submit — each with `to`, `data`, `value`, `chainId`. It is BUILT +
/// READY, deliberately UNSIGNED: the Postern wallet is post-quantum
/// Bloch-native (Falcon‖ML-DSA), not a secp256k1 EVM signer, and no L2 is live
/// to accept it. Nothing here is broadcast.
#[tauri::command]
pub fn swap_build_tx(args: BuildArgs) -> Result<Value, String> {
    let router = if args.router.trim().is_empty() {
        ROUTER02.to_string()
    } else {
        args.router.trim().to_string()
    };
    let chain_id = L2_CHAIN_ID;
    let steps: Vec<Value> = match args.kind.as_str() {
        "wrap" => {
            let amount = parse_u256_dec(&args.amount_in)?;
            vec![json!({
                "label": "Wrap: WBLCH.deposit() — lock native BLCH, mint wBLCH 1:1",
                "to": WBLCH_PREDEPLOY,
                "data": build_deposit(),
                "value": amount.to_string(),
                "chainId": chain_id,
            })]
        }
        "unwrap" => {
            let amount = parse_u256_dec(&args.amount_in)?;
            vec![json!({
                "label": "Unwrap: WBLCH.withdraw(wad) — burn wBLCH, release native BLCH 1:1",
                "to": WBLCH_PREDEPLOY,
                "data": build_withdraw(amount)?,
                "value": "0",
                "chainId": chain_id,
            })]
        }
        "swap" => {
            let amount_in = parse_u256_dec(&args.amount_in)?;
            let amount_out_min = parse_u256_dec(&args.amount_out_min)?;
            let deadline = parse_u256_dec(&args.deadline)?;
            let token_in = &args.token_in;
            let token_out = &args.token_out;
            let to = &args.recipient;
            vec![
                json!({
                    "label": "Approve: ERC-20 approve(router, amountIn) on the input token",
                    "to": token_in,
                    "data": build_approve(&router, amount_in)?,
                    "value": "0",
                    "chainId": chain_id,
                }),
                json!({
                    "label": "Swap: Router.swapExactTokensForTokens(amountIn, amountOutMin, [in,out], to, deadline)",
                    "to": router,
                    "data": build_swap(amount_in, amount_out_min, token_in, token_out, to, deadline)?,
                    "value": "0",
                    "chainId": chain_id,
                }),
            ]
        }
        other => return Err(format!("unknown build kind '{other}' (expected swap|wrap|unwrap)")),
    };
    Ok(json!({
        "steps": steps,
        "router": router,
        "wblch": WBLCH_PREDEPLOY,
        "chainId": chain_id,
        "signed": false,
        "note": "Built + READY, UNSIGNED. No EVM signer is wired (the wallet is PQ Bloch-native, not secp256k1) and no L2 is live to accept it.",
        "honesty": HONESTY,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeArgs {
    pub rpc_url: String,
    #[serde(default)]
    pub allow_custom: bool,
}

/// REAL JSON-RPC liveness probe against a configured L2 EVM endpoint. Honest by
/// construction: it makes a genuine `eth_chainId` + `eth_blockNumber` call and
/// reports exactly what came back — or `reachable: false` with the transport
/// error. It NEVER fabricates a chain, block, or hash. The URL is allowlisted
/// via the same [`crate::validate_rpc_url`] gate the node RPC uses (a loopback
/// http devnet passes without confirmation; a remote endpoint needs
/// `allow_custom`), so this can't be turned into an SSRF client.
#[tauri::command]
pub fn swap_l2_probe(args: ProbeArgs) -> Result<Value, String> {
    let url = args.rpc_url.trim();
    crate::validate_rpc_url(url, args.allow_custom)?;
    let call = |method: &str| -> Result<String, String> {
        let resp = ureq::post(url)
            .timeout(std::time::Duration::from_secs(8))
            .set("content-type", "application/json")
            .send_json(json!({"jsonrpc":"2.0","id":1,"method":method,"params":[]}))
            .map_err(|e| format!("{method}: {e}"))?;
        let v: Value = resp
            .into_json()
            .map_err(|e| format!("{method}: bad JSON response: {e}"))?;
        if let Some(err) = v.get("error") {
            return Err(format!("{method}: rpc error {err}"));
        }
        v.get("result")
            .and_then(|r| r.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| format!("{method}: missing/blank result"))
    };

    match call("eth_chainId") {
        Ok(chain_hex) => {
            let chain_id = u64::from_str_radix(chain_hex.trim_start_matches("0x"), 16).ok();
            let block = call("eth_blockNumber").ok().and_then(|b| {
                u64::from_str_radix(b.trim_start_matches("0x"), 16).ok()
            });
            let is_bloch_l2 = chain_id == Some(L2_CHAIN_ID);
            Ok(json!({
                "reachable": true,
                "chainId": chain_id,
                "chainIdHex": chain_hex,
                "blockNumber": block,
                "isBlochL2": is_bloch_l2,
                "note": if is_bloch_l2 {
                    "An EVM endpoint answered with chain_id 700771. NOTE: 700771 is unregistered — this is a local/self-hosted L2 devnet, not a public network. Execution stays PREVIEW (no EVM signer is wired)."
                } else {
                    "An EVM endpoint answered, but its chain_id is not 700771 — not the Bloch L2. Refusing to treat it as PosternDex's chain."
                },
                "honesty": HONESTY,
            }))
        }
        Err(e) => Ok(json!({
            "reachable": false,
            "chainId": Value::Null,
            "blockNumber": Value::Null,
            "isBlochL2": false,
            "note": format!("No live L2 EVM endpoint reachable ({e}). This is expected: the Bloch L2 is design-scaffold. The swap tx is BUILT + READY; it will execute once a live L2 devnet/mainnet exists."),
            "honesty": HONESTY,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> U256 {
        U256::from_dec_str(s).unwrap()
    }

    #[test]
    fn get_amount_out_known_uniswap_vector() {
        // Canonical Uniswap v2 vector: getAmountOut(1000, 5000, 10000) == 1662.
        let out = get_amount_out(u("1000"), u("5000"), u("10000"), 30).unwrap();
        assert_eq!(out, u("1662"));
    }

    #[test]
    fn get_amount_out_second_vector() {
        // getAmountOut(1_000_000, 10_000_000, 20_000_000) with 0.30% fee.
        // amountInWithFee = 1_000_000*997 = 997_000_000
        // num = 997_000_000 * 20_000_000 = 19_940_000_000_000_000
        // den = 10_000_000*1000 + 997_000_000 = 10_997_000_000
        // out = 19_940_000_000_000_000 / 10_997_000_000 = 1_813_221 (floored)
        let out = get_amount_out(u("1000000"), u("10000000"), u("20000000"), 30).unwrap();
        assert_eq!(out, u("1813221"));
    }

    #[test]
    fn get_amount_out_handles_18dp_wei_without_overflow() {
        // 1000 wBLCH in, a 1M / 3.5M-token pool, all in 18-dp wei. This overflows
        // u128 in the intermediate product; U256 handles it.
        let one = u("1000000000000000000"); // 1e18
        let amount_in = u("1000") * one;
        let reserve_in = u("1000000") * one;
        let reserve_out = u("3500000") * one;
        let out = get_amount_out(amount_in, reserve_in, reserve_out, 30).unwrap();
        assert!(out > U256::zero());
        // Output must be strictly less than the naive mid-price product (fee +
        // slippage), and less than the whole reserve.
        assert!(out < reserve_out);
        let mid_price_out = amount_in * reserve_out / reserve_in; // no-fee, no-slippage
        assert!(out < mid_price_out, "real out must be below the frictionless mid quote");
    }

    #[test]
    fn zero_liquidity_and_zero_input_fail_closed() {
        assert!(get_amount_out(u("100"), u("0"), u("10000"), 30).is_err());
        assert!(get_amount_out(u("100"), u("5000"), u("0"), 30).is_err());
        assert!(get_amount_out(u("0"), u("5000"), u("10000"), 30).is_err());
    }

    #[test]
    fn price_impact_is_monotonic_in_amount_in() {
        let ri = u("1000000");
        let ro = u("1000000");
        let mut last = 0u64;
        for a in ["1000", "10000", "100000", "500000"] {
            let ain = u(a);
            let out = get_amount_out(ain, ri, ro, 30).unwrap();
            let imp = price_impact_bps(ain, out, ri, ro).unwrap();
            assert!(imp >= last, "impact must not decrease as amount-in grows");
            last = imp;
        }
        // A dust trade floors near the LP fee (~0.30%) — the impact reported is
        // realized-vs-mid, which INCLUDES the fee; it must be small and far
        // below the whale trade. (A 1-wei trade would round output to 0 here —
        // a degenerate case, not "zero impact" — so use a non-dusting amount.)
        let dust_in = u("1000");
        let dust_out = get_amount_out(dust_in, ri, ro, 30).unwrap();
        let dust_impact = price_impact_bps(dust_in, dust_out, ri, ro).unwrap();
        assert!(dust_impact <= 60, "dust impact must be tiny (got {dust_impact} bps)");
        assert!(dust_impact < last, "dust impact must be far below a whale trade");
        assert!(last > 3000, "a 50%-of-reserve trade should show >30% impact");
    }

    #[test]
    fn min_received_applies_slippage() {
        // 1% slippage on 10000 → 9900.
        assert_eq!(min_received(u("10000"), 100).unwrap(), u("9900"));
        // 0 slippage → unchanged.
        assert_eq!(min_received(u("10000"), 0).unwrap(), u("10000"));
    }

    #[test]
    fn selectors_match_known_evm_4byte_signatures() {
        assert_eq!(hex::encode(selector("approve(address,uint256)")), "095ea7b3");
        assert_eq!(hex::encode(selector("deposit()")), "d0e30db0");
        assert_eq!(hex::encode(selector("withdraw(uint256)")), "2e1a7d4d");
        assert_eq!(
            hex::encode(selector(
                "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)"
            )),
            "38ed1739"
        );
    }

    #[test]
    fn approve_calldata_is_exact() {
        let router = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D";
        let data = build_approve(router, u("1000000000000000000")).unwrap();
        // selector ‖ padded router ‖ 1e18
        assert_eq!(
            data,
            "0x095ea7b3\
             0000000000000000000000007a250d5630b4cf539739df2c5dacb4c659f2488d\
             0000000000000000000000000000000000000000000000000de0b6b3a7640000"
        );
    }

    #[test]
    fn swap_calldata_has_selector_offset_and_path() {
        let wblch = "0x4200000000000000000000000000000000000006";
        let tok = "0x00000000000000000000000000000000000000aa";
        let to = "0x00000000000000000000000000000000000000bb";
        let data = build_swap(u("1000"), u("990"), wblch, tok, to, u("1893456000")).unwrap();
        let body = data.strip_prefix("0x").unwrap();
        assert_eq!(&body[..8], "38ed1739"); // selector
        // word3 (offset 2, chars 8+64*2 .. ) is the array offset 0xa0 = 160.
        let off_word = &body[8 + 64 * 2..8 + 64 * 3];
        assert_eq!(
            off_word,
            "00000000000000000000000000000000000000000000000000000000000000a0"
        );
        // path length word == 2, then the two token addresses.
        let len_word = &body[8 + 64 * 5..8 + 64 * 6];
        assert_eq!(
            len_word,
            "0000000000000000000000000000000000000000000000000000000000000002"
        );
        assert!(body.contains("4200000000000000000000000000000000000006"));
        // to (recipient, ...bb) is word[3]; the LAST word is path[1] = tokenOut (...aa).
        let to_word = &body[8 + 64 * 3..8 + 64 * 4];
        assert!(to_word.ends_with("00000000000000000000000000000000000000bb"));
        assert!(body.ends_with("00000000000000000000000000000000000000aa"));
    }

    #[test]
    fn quote_command_roundtrips_and_carries_honesty() {
        let args = QuoteArgs {
            amount_in: "1000".into(),
            reserve_in: "5000".into(),
            reserve_out: "10000".into(),
            fee_bps: 30,
            slippage_bps: 50,
        };
        let v = swap_quote(args).unwrap();
        assert_eq!(v["amountOut"], "1662");
        // min received at 0.50% slippage: 1662 * 9950 / 10000 = 1653 (floored).
        assert_eq!(v["minReceived"], "1653");
        assert!(v["honesty"].as_str().unwrap().contains("NOT live"));
    }
}
