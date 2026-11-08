// Postern Mobile — pure-core fidelity tests (node --test).
//
// The shell imports src/lib/wallet-core.js, which is EXTRACTED from
// apps/mobile-wallet's host-tested <script id="wallet-core"> block. These tests
// guard that the extraction stays byte-faithful to Bloch core: SHA3-256 against
// NIST vectors, byte-identical JSON-RPC request bodies, the fail-closed u64
// parser, and amount round-tripping. No DOM, no network, no fabricated values.
import test from 'node:test';
import assert from 'node:assert/strict';
import WALLET from '../src/lib/wallet-core.js';

const enc = new TextEncoder();
const hex = (b) => WALLET.toHex(b);

test('WALLET core module loads with expected surface', () => {
  assert.equal(typeof WALLET.sha3_256, 'function');
  assert.equal(typeof WALLET.getbalanceRequest, 'function');
  assert.equal(typeof WALLET.parseU64Result, 'function');
  assert.equal(typeof WALLET.parseCoins, 'function');
});

test('SHA3-256 empty-string NIST vector', () => {
  assert.equal(
    hex(WALLET.sha3_256(enc.encode(''))),
    'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
  );
});

test("SHA3-256 'abc' NIST vector", () => {
  assert.equal(
    hex(WALLET.sha3_256(enc.encode('abc'))),
    '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
  );
});

test('SHA3-256 multi-block (200 x 0xa3) known vector', () => {
  const msg = new Uint8Array(200).fill(0xa3);
  assert.equal(
    hex(WALLET.sha3_256(msg)),
    '79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787',
  );
});

test('JSON-RPC request bodies are byte-identical to bloch-mobile', () => {
  assert.equal(
    WALLET.getbalanceRequest('blk1abc'),
    '{"jsonrpc":"2.0","id":1,"method":"getbalance","params":["blk1abc"]}',
  );
  assert.equal(
    WALLET.getblockcountRequest(),
    '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}',
  );
  assert.equal(
    WALLET.sendrawtransactionRequest('deadbeef'),
    '{"jsonrpc":"2.0","id":1,"method":"sendrawtransaction","params":["deadbeef"]}',
  );
});

test('parseU64Result accepts int + result.balance, throws on rpc error', () => {
  assert.equal(WALLET.parseU64Result('{"jsonrpc":"2.0","id":1,"result":123456}'), 123456);
  assert.equal(WALLET.parseU64Result('{"result":{"balance":777}}'), 777);
  assert.throws(
    () => WALLET.parseU64Result('{"error":{"code":-1,"message":"nope"},"result":null}'),
    /rpc error/,
  );
});

test('amount math round-trips and fails closed', () => {
  assert.equal(WALLET.parseCoins('1.5'), 150000000);
  assert.equal(WALLET.parseCoins('0.00000001'), 1);
  assert.equal(WALLET.fmtCoins(150000000), '1.50000000');
  assert.throws(() => WALLET.parseCoins('1.234567890'), /8 decimals/);
  assert.throws(() => WALLET.parseCoins('90071992.54740992'), /too large/);
});

test('address validation is fail-closed on network + charset', () => {
  assert.equal(WALLET.validateAddress('blk1qqqqqqqq', false), true);
  assert.throws(() => WALLET.validateAddress('tblk1qqqqqqqq', false), /other network/);
  assert.throws(() => WALLET.validateAddress('blk1IIII', false), /charset|invalid character/);
});
