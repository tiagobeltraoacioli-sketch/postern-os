/* ============================================================================
   Postern Wallet — mobile PWA · honest copy (single source of truth)
   ============================================================================
   Every honesty claim the app makes lives here so it is (a) written once,
   (b) reused verbatim by every screen, and (c) machine-checkable: test/honesty.mjs
   greps the BUILT dist/ and asserts each REQUIRED phrase is present and none of
   the BANNED overclaims are. If you weaken a claim, the test fails the build.

   Ground rules encoded below:
     • Unaudited reference prototype — no security audit.
     • The keys are a SOFTWARE keystore in this browser tab; it is NOT the phone's
       Secure Enclave / StrongBox, and installing the PWA is not a security upgrade.
       (Deliberately never uses the phrase "hardware-backed" — this app is not.)
     • BLCH carries no value claim: worthless by design, not a security.
     • Reads are real via the hosted, same-origin /rpc proxy — no live node
       required on the phone; the node lives behind /rpc.
     • Never a faked balance/sign/tx. Where a piece is not wired, it is labelled a
       preview, not a result.
   ============================================================================ */

// ── the four machine-required phrases (verbatim, reused everywhere) ──────────

/** Audit status. Contains "Unaudited" and "no security audit". */
export const AUDIT_STATUS =
  "Unaudited reference prototype — no security audit. Do not trust it with value.";

/**
 * Keystore honesty. Contains "software keystore" + "not" + "Secure Enclave" and
 * "StrongBox". Never says "hardware-backed": this app is not.
 */
export const KEYSTORE_HONEST =
  "Your keys are a software keystore in this browser tab — it is not the phone's " +
  "Secure Enclave or StrongBox, and installing this PWA is not a security upgrade.";

/** Coin honesty. Contains "no value" and "worthless by design". */
export const COIN_HONEST =
  "BLCH carries no value claim: it is worthless by design and is not a security.";

/**
 * Node-access honesty — MUST match test/honesty.mjs REQUIRED string exactly,
 * em dash included: "reads via the hosted /rpc — no live node required".
 */
export const RPC_HONEST =
  "Balances and block height are real: the wallet reads via the hosted /rpc — " +
  "no live node required on this phone; the same-origin proxy forwards to the " +
  "canonical Bloch node over HTTPS.";

/** Funds honesty — no real funds move unless the real signed-send path is wired. */
export const FUNDS_HONEST =
  "Moves no real funds unless the real send path is genuinely wired; a signed " +
  "transfer is irreversible and is only ever built from bytes you can see (WYSIWYS).";

/** The persistent top banner shown on every screen. */
export const TOP_BANNER =
  "REFERENCE PROTOTYPE · UNAUDITED · SOFTWARE KEYSTORE · BLCH HAS NO VALUE";

/** All honest lines, so any screen can render the full disclosure block. */
export const HONEST_LINES: ReadonlyArray<{ id: string; text: string }> = [
  { id: "audit", text: AUDIT_STATUS },
  { id: "keystore", text: KEYSTORE_HONEST },
  { id: "coin", text: COIN_HONEST },
  { id: "rpc", text: RPC_HONEST },
  { id: "funds", text: FUNDS_HONEST },
];
