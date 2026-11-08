// Postern Wallet — mobile touch UI — pure-core tests. Run with: node test-core.mjs (Node >= 18)
//
// Extracts the DOM-free <script id="wallet-core"> block from index.html and
// exercises the trust-bearing logic on the HOST: SHA3-256 against NIST vectors,
// the JSON-RPC request builders (byte-identical to bloch-mobile's core), the
// u64 result parser, WYSIWYS tier/sentence/confirmation-fragment, and the
// fail-closed transfer decoder (multi-output refused). No DOM, no network.
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";

const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
const m = html.match(/<script id="wallet-core">([\s\S]*?)<\/script>/);
assert.ok(m, "wallet-core script block found");
(0, eval)(m[1]);
const W = globalThis.WALLET;
assert.ok(W && typeof W.sha3_256 === "function", "WALLET core loaded");

let passed = 0;
const t = (name, fn) => { fn(); passed++; console.log("  ok — " + name); };
const enc = new TextEncoder();
const hex = b => W.toHex(b);

// ── SHA3-256 (byte-faithful to the Rust signer's SHA3) ────────────────────
t("SHA3-256 empty-string NIST vector", () => {
  assert.equal(hex(W.sha3_256(enc.encode(""))),
    "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
});
t("SHA3-256 'abc' NIST vector", () => {
  assert.equal(hex(W.sha3_256(enc.encode("abc"))),
    "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
});
t("SHA3-256 multi-block (>136 bytes) matches known vector", () => {
  // 200 bytes of 0xA3 — a standard Keccak/SHA3 test input spanning >1 block.
  const msg = new Uint8Array(200).fill(0xa3);
  assert.equal(hex(W.sha3_256(msg)),
    "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787");
});

// ── JSON-RPC seam: exact bytes bloch-mobile builds ────────────────────────
t("getbalance request body is byte-identical to bloch-mobile", () => {
  assert.equal(W.getbalanceRequest("blk1abc"),
    '{"jsonrpc":"2.0","id":1,"method":"getbalance","params":["blk1abc"]}');
});
t("getblockcount request body", () => {
  assert.equal(W.getblockcountRequest(),
    '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}');
});
t("sendrawtransaction request body", () => {
  assert.equal(W.sendrawtransactionRequest("deadbeef"),
    '{"jsonrpc":"2.0","id":1,"method":"sendrawtransaction","params":["deadbeef"]}');
});
t("parseU64Result: plain integer result", () => {
  assert.equal(W.parseU64Result('{"jsonrpc":"2.0","id":1,"result":123456}'), 123456);
});
t("parseU64Result: result.balance object", () => {
  assert.equal(W.parseU64Result('{"result":{"balance":777}}'), 777);
});
t("parseU64Result: non-null error throws (no false balance)", () => {
  assert.throws(() => W.parseU64Result('{"error":{"code":-1,"message":"nope"},"result":null}'), /rpc error/);
});

// ── amount round-trip (sats <-> BLOCH) ────────────────────────────────────
t("parseCoins / fmtCoins round-trip and reject junk", () => {
  assert.equal(W.parseCoins("1.5"), 150000000);
  assert.equal(W.parseCoins("0.00000001"), 1);
  assert.equal(W.fmtCoins(150000000), "1.50000000");
  assert.equal(W.fmtCoins(1342500000), "13.42500000");
  assert.throws(() => W.parseCoins("1.234567890"), /8 decimals/); // over-precision refused
  assert.throws(() => W.parseCoins("abc"), /number/);
});
t("parseCoins fails closed on amounts too large to represent safely (no silent precision loss)", () => {
  // Number.MAX_SAFE_INTEGER (9007199254740991) sats == 90071992.54740991 BLOCH exactly.
  assert.equal(W.parseCoins("90071992.54740991"), Number.MAX_SAFE_INTEGER);
  // one more sat must be REJECTED, not silently rounded to a wrong amount via float imprecision
  assert.throws(() => W.parseCoins("90071992.54740992"), /too large/);
  assert.throws(() => W.parseCoins("99999999999999999999.99999999"), /too large/);
});

// ── WYSIWYS: tiers, sentence, can_move_funds ──────────────────────────────
const session = Uint8Array.from([0xB1,0x0C,0x48,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD]);
const nonce = new Uint8Array(32).fill(7);

t("login derives SingleTap, cannot move funds", () => {
  const w = W.render({ type:"login", user:"tiago", org:"Postern Labs" }, {peer_device:"Desktop", session, nonce});
  assert.equal(w.tier, "SingleTap");
  assert.equal(w.can_move_funds, false);
  assert.match(w.sentence, /login challenge/);
  assert.match(w.sentence, /can't move funds/);
});
t("transfer derives ExplicitReview, moves funds, carries fee-unverifiable disclosure", () => {
  const w = W.render({ type:"transfer", chain:"testnet", input_count:2, declared_fee_sats:12000,
    outputs:[{recipient:"blk1dest", value_sats:250000000}] }, {peer_device:"Desktop", session, nonce, wallet_chain:"testnet"});
  assert.equal(w.tier, "ExplicitReview");
  assert.equal(w.can_move_funds, true);
  assert.match(w.sentence, /moves 2\.50000000 BLOCH to blk1dest/);
  assert.match(w.sentence, /irreversibl/);
  assert.ok(w.disclosures.some(d => /NOT verifiable from the transaction bytes/.test(d)), "fee-unverifiable disclosure present");
  assert.ok(w.disclosures.some(d => /Falcon-1024 . ML-DSA-65/.test(d)), "PQ signing-model disclosure present");
});

// ── SECURITY REGRESSION: WYSIWYS network must come from the wallet, never
// from the (possibly adversarial) request payload — a malicious phone-as-
// signer peer must not be able to spoof which chain is displayed. ──────────
t("render() ignores a payload-supplied chain and displays the WALLET's own network instead", () => {
  const w = W.render({ type:"transfer", chain:"mainnet", input_count:1, declared_fee_sats:0,
    outputs:[{recipient:"blk1dest", value_sats:1}] }, {session, nonce, wallet_chain:"testnet"});
  assert.match(w.sentence, /testnet/, "must show the wallet's real network");
  assert.doesNotMatch(w.sentence, /mainnet/, "must NOT trust the request's claimed network");
});
t("render() fails closed on a transfer when the caller omits wallet_chain (no trusting the request as a fallback)", () => {
  assert.throws(() => W.render({ type:"transfer", chain:"mainnet",
    outputs:[{recipient:"blk1dest", value_sats:1}] }, {session, nonce}),
    e => e.kind === "Undecodable");
});

// ── address validation (fail-closed shape check for the SEND flow) ───────
t("validateAddress accepts a well-formed address for the matching network", () => {
  assert.equal(W.validateAddress(W.demoAddress("seed", 0, true), true), true);
  assert.equal(W.validateAddress(W.demoAddress("seed", 0, false), false), true);
});
t("validateAddress rejects a wrong-network prefix (fail-closed, not a silent cross-network send)", () => {
  const mainnetAddr = W.demoAddress("seed", 0, false);
  assert.throws(() => W.validateAddress(mainnetAddr, true), /other network/);
});
t("validateAddress rejects malformed/garbage input", () => {
  assert.throws(() => W.validateAddress("", true));
  assert.throws(() => W.validateAddress("<script>alert(1)</script>", true));
  assert.throws(() => W.validateAddress("blk1", false), /implausible/);
  assert.throws(() => W.validateAddress("blk1UPPERCASE_not_allowed", false));
});

// ── confirmation fragment = SHA3-256(domain ‖ session ‖ nonce)[..3] ────────
t("confirmationFragment: deterministic, 6 hex chars, domain-bound", () => {
  const f = W.confirmationFragment(session, nonce);
  assert.match(f, /^[0-9a-f]{6}$/);
  // recompute the exact preimage the Rust signer uses, independently
  const pre = W.concat(enc.encode("postern:approval-fragment:v1"), session, nonce);
  assert.equal(f, W.toHex(W.sha3_256(pre).subarray(0,3)));
  // a different nonce yields a different fragment (binding holds)
  assert.notEqual(f, W.confirmationFragment(session, new Uint8Array(32).fill(8)));
});

// ── fail-closed transfer decoding ─────────────────────────────────────────
t("single-output transfer reduces to one intent", () => {
  const it = W.toTransferIntent({ chain:"mainnet", input_count:1, declared_fee_sats:500,
    outputs:[{recipient:"blk1x", value_sats:1000}] });
  assert.equal(it.to_address, "blk1x");
  assert.equal(it.amount_sats, 1000);
});
t("multi-output transfer is REFUSED (fail-closed, not under-displayed)", () => {
  assert.throws(() => W.toTransferIntent({ chain:"mainnet", outputs:[
    {recipient:"a",value_sats:1},{recipient:"b",value_sats:2}] }),
    e => e.kind === "MultiOutput");
});
t("zero-output transfer is refused", () => {
  assert.throws(() => W.toTransferIntent({ chain:"mainnet", outputs:[] }), e => e.kind === "NoOutputs");
});
t("unknown payload type fails closed in deriveTier", () => {
  assert.throws(() => W.deriveTier({ type:"totally-unknown-op" }), e => e.kind === "Undecodable");
});
t("render() propagates fail-closed refusal for a multi-output transfer", () => {
  assert.throws(() => W.render({ type:"transfer", chain:"testnet",
    outputs:[{recipient:"a",value_sats:1},{recipient:"b",value_sats:2}] }, {session, nonce}),
    e => e.kind === "MultiOutput");
});

// ── receive fallback helpers ──────────────────────────────────────────────
t("groupAddress splits into fixed-size verifiable groups", () => {
  assert.deepEqual(W.groupAddress("abcdefghij", 4), ["abcd","efgh","ij"]);
});
t("fingerprintCells is 11x11, deterministic, and left-right mirrored", () => {
  const c = W.fingerprintCells("blk1demo");
  assert.equal(c.length, 11);
  assert.equal(c[0].length, 11);
  for (let y=0;y<11;y++) for (let x=0;x<11;x++) assert.equal(c[y][x], c[y][10-x], "mirror axis holds");
  assert.deepEqual(c, W.fingerprintCells("blk1demo")); // deterministic
});

// ── demo material is deterministic and labeled-illustrative shape ─────────
t("demoAddress is deterministic and network-prefixed", () => {
  assert.equal(W.demoAddress("aa", 0, true), W.demoAddress("aa", 0, true));
  assert.ok(W.demoAddress("aa", 0, true).startsWith("tblk1"));
  assert.ok(W.demoAddress("aa", 0, false).startsWith("blk1"));
  assert.notEqual(W.demoAddress("aa", 0, true), W.demoAddress("aa", 1, true)); // diversified
});
t("demoMnemonic yields the requested word count from the sample list", () => {
  const words = W.demoMnemonic("seed", 12);
  assert.equal(words.length, 12);
  words.forEach(w => assert.ok(W.WORDS.includes(w)));
});

console.log("\n  " + passed + " passed.");
