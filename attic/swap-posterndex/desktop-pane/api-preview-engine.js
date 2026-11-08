// EXTRACTED from desktop/src/api.js (lines 899-1007) when Swap/PosternDex were
// withdrawn on 2026-07-18. Browser-side preview engine mirroring
// desktop/src-tauri/src/swap.rs. To restore: paste back into api.js's preview
// section, just before the final `})();`, and re-add swap_quote/swap_build_tx/
// swap_l2_probe to the REAL set.

  // ═════════════════════════════════════════════════════════════════════
  // SWAP / DEX preview engine — mirrors desktop/src-tauri/src/swap.rs. The
  // constant-product quote (getAmountOut + price impact + slippage floor) and
  // the EVM calldata builder are REAL, pure functions here too: JS BigInt is
  // arbitrary-precision, so the 18-dp wei math is byte-identical to the Rust
  // U256 path (this is the same "real in preview" stance as the courier/hygiene
  // engines, not a fake). Only network EXECUTION needs the backend, so
  // swap_l2_probe's preview returns the honest not-reachable state.
  // HONESTY (unconditional): PosternDex + the Bloch EVM L2 are DESIGN-SCAFFOLD,
  // NOT live; on-chain execution is PREVIEW; no tx is ever signed or broadcast.
  // ═════════════════════════════════════════════════════════════════════
  const SWAP_HONESTY = "PosternDex + the Bloch EVM L2 are DESIGN-SCAFFOLD, NOT live: chain_id 700771 is unregistered, no L2 node/RPC/prover runs, WBLCH is a genesis predeploy never actually deployed, and no pools exist. The constant-product quote math and the EVM calldata are REAL and tested offline; on-chain EXECUTION is PREVIEW until a live L2 (or local devnet) exists. The v1 bridge vault is CUSTODY. Zero-value; BLCH/wBLCH are worthless; unaudited.";
  const SWAP_L2_CHAIN_ID = 700771;
  const SWAP_WBLCH = "0x4200000000000000000000000000000000000006";
  const SWAP_ROUTER02 = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D";
  // Well-known EVM 4-byte selectors (keccak256(signature)[..4]). The Rust side
  // (swap.rs tests) verifies each against its signature; here they are pinned
  // constants so the preview needs no keccak bundle.
  const SWAP_SELECTORS = {
    approve: "095ea7b3",       // approve(address,uint256)
    deposit: "d0e30db0",       // deposit()
    withdraw: "2e1a7d4d",      // withdraw(uint256)
    swapExact: "38ed1739",     // swapExactTokensForTokens(uint256,uint256,address[],address,uint256)
  };
  const swapU = (s) => {
    const t = String(s == null ? "" : s).trim();
    if (!/^\d+$/.test(t)) throw `invalid decimal integer '${t}'`;
    return BigInt(t);
  };
  const swapWord = (v) => BigInt(v).toString(16).padStart(64, "0");
  const swapAddrWord = (a) => {
    const h = String(a || "").trim().replace(/^0x/i, "").toLowerCase();
    if (!/^[0-9a-f]{40}$/.test(h)) throw `address '${a}' must be 20 bytes (40 hex chars)`;
    return h.padStart(64, "0");
  };
  // REAL getAmountOut — Uniswap-v2 constant product with the pool fee (bps).
  function swapAmountOut(amountIn, reserveIn, reserveOut, feeBps) {
    if (amountIn <= 0n) throw "INSUFFICIENT_INPUT_AMOUNT: amount-in must be greater than zero";
    if (reserveIn <= 0n || reserveOut <= 0n) throw "INSUFFICIENT_LIQUIDITY: both pool reserves must be greater than zero";
    if (feeBps >= 10000) throw "fee_bps must be less than 10000 (100%)";
    const amountInWithFee = amountIn * BigInt(10000 - feeBps);
    const numerator = amountInWithFee * reserveOut;
    const denominator = reserveIn * 10000n + amountInWithFee;
    return numerator / denominator;
  }
  function swapImpactBps(amountIn, amountOut, reserveIn, reserveOut) {
    if (amountIn <= 0n || reserveOut <= 0n) throw "cannot compute price impact with zero input or zero reserve";
    const ratioBps = (amountOut * reserveIn * 10000n) / (amountIn * reserveOut);
    return ratioBps >= 10000n ? 0 : Number(10000n - ratioBps);
  }
  function swapMinReceived(amountOut, slippageBps) {
    if (slippageBps >= 10000) throw "slippage_bps must be less than 10000 (100%)";
    return (amountOut * BigInt(10000 - slippageBps)) / 10000n;
  }

  preview.swap_quote = async ({ amountIn, reserveIn, reserveOut, feeBps = 30, slippageBps = 0 }) => {
    const ain = swapU(amountIn), ri = swapU(reserveIn), ro = swapU(reserveOut);
    const out = swapAmountOut(ain, ri, ro, feeBps);
    return {
      amountOut: out.toString(),
      minReceived: swapMinReceived(out, slippageBps).toString(),
      priceImpactBps: swapImpactBps(ain, out, ri, ro),
      feeBps, slippageBps,
      honesty: SWAP_HONESTY,
    };
  };

  preview.swap_build_tx = async (a) => {
    const kind = a.kind;
    const router = (a.router && String(a.router).trim()) || SWAP_ROUTER02;
    const chainId = SWAP_L2_CHAIN_ID;
    let steps;
    if (kind === "wrap") {
      const amount = swapU(a.amountIn);
      steps = [{ label: "Wrap: WBLCH.deposit() — lock native BLCH, mint wBLCH 1:1",
        to: SWAP_WBLCH, data: "0x" + SWAP_SELECTORS.deposit, value: amount.toString(), chainId }];
    } else if (kind === "unwrap") {
      const amount = swapU(a.amountIn);
      steps = [{ label: "Unwrap: WBLCH.withdraw(wad) — burn wBLCH, release native BLCH 1:1",
        to: SWAP_WBLCH, data: "0x" + SWAP_SELECTORS.withdraw + swapWord(amount), value: "0", chainId }];
    } else if (kind === "swap") {
      const amountIn = swapU(a.amountIn);
      const amountOutMin = swapU(a.amountOutMin);
      const deadline = swapU(a.deadline);
      const approveData = "0x" + SWAP_SELECTORS.approve + swapAddrWord(router) + swapWord(amountIn);
      const swapData = "0x" + SWAP_SELECTORS.swapExact +
        swapWord(amountIn) + swapWord(amountOutMin) + swapWord(160n) +
        swapAddrWord(a.recipient) + swapWord(deadline) +
        swapWord(2n) + swapAddrWord(a.tokenIn) + swapAddrWord(a.tokenOut);
      steps = [
        { label: "Approve: ERC-20 approve(router, amountIn) on the input token",
          to: a.tokenIn, data: approveData, value: "0", chainId },
        { label: "Swap: Router.swapExactTokensForTokens(amountIn, amountOutMin, [in,out], to, deadline)",
          to: router, data: swapData, value: "0", chainId },
      ];
    } else {
      throw `unknown build kind '${kind}' (expected swap|wrap|unwrap)`;
    }
    return { steps, router, wblch: SWAP_WBLCH, chainId, signed: false,
      note: "Built + READY, UNSIGNED. No EVM signer is wired (the wallet is PQ Bloch-native, not secp256k1) and no L2 is live to accept it.",
      honesty: SWAP_HONESTY };
  };

  // No backend → the browser preview cannot reach an L2 RPC. Honest, never faked.
  preview.swap_l2_probe = async () => ({
    reachable: false, chainId: null, blockNumber: null, isBlochL2: false,
    note: "No live L2 EVM endpoint (browser preview cannot open a network socket, and the Bloch L2 is design-scaffold). The swap tx is BUILT + READY; it will execute once a live L2 devnet/mainnet exists. Run the native Postern Desktop app to probe a configured/local L2 RPC for real.",
    honesty: SWAP_HONESTY,
  });
