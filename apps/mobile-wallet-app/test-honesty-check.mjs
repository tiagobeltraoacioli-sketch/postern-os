#!/usr/bin/env node
// test-honesty-check.mjs — headless unit + end-to-end tests for the honesty
// ship-gate. Uses node:test (no deps). Covers:
//   1. unit: checkScreen() flags exactly the missing disclosures.
//   2. unit: HONESTY_COPY satisfies every mandatory check.
//   3. e2e:  a GOOD dist (every screen carries all copy) exits 0.
//   4. e2e:  a BAD dist (one screen drops "not a security") exits 1 and names it.
//   5. e2e:  each single dropped disclosure fails (per-phrase coverage).
//   6. e2e:  fail-closed — no manifest / empty manifest / missing screen file / no dist.
//   7. e2e:  the shipped example-dist passes (contract stays green).
//   8. e2e:  glob + files[] screen resolution and code-split copy both work.
//
// Run: node apps/mobile-wallet-app/test-honesty-check.mjs

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { checkScreen, HONESTY_COPY, REQUIRED, run } from './honesty-check.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CHECKER = path.join(HERE, 'honesty-check.mjs');

function mkdist(screens, { manifest = true, manifestBody } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'honesty-'));
  fs.mkdirSync(path.join(dir, 'assets'), { recursive: true });
  const entries = [];
  for (const [id, text] of Object.entries(screens)) {
    const rel = `assets/${id}.js`;
    fs.writeFileSync(path.join(dir, rel), text);
    entries.push({ id, file: rel });
  }
  if (manifest) {
    fs.writeFileSync(
      path.join(dir, 'honesty-manifest.json'),
      manifestBody !== undefined ? manifestBody : JSON.stringify({ screens: entries }),
    );
  }
  return dir;
}

// Spawn the checker as a real process; return { code, stderr, stdout }.
function runCli(dist, extra = []) {
  try {
    const stdout = execFileSync('node', [CHECKER, '--dist', dist, ...extra], { encoding: 'utf8' });
    return { code: 0, stdout, stderr: '' };
  } catch (e) {
    return { code: e.status ?? 1, stdout: e.stdout || '', stderr: e.stderr || '' };
  }
}

const GOOD = HONESTY_COPY;

test('unit: HONESTY_COPY satisfies every mandatory disclosure', () => {
  assert.deepEqual(checkScreen(HONESTY_COPY), []);
});

test('unit: empty text is missing all disclosures', () => {
  const missing = checkScreen('hello world');
  assert.equal(missing.length, REQUIRED.length);
});

test('unit: dropping "not a security" is detected', () => {
  const weakened = HONESTY_COPY.replace('and is not a security', '');
  const missing = checkScreen(weakened);
  assert.ok(missing.some((m) => /not a security/i.test(m)), `expected coin check to fail, got ${JSON.stringify(missing)}`);
});

test('unit: markup/JSX variants still match', () => {
  const jsx =
    '<p>This is a <strong>reference&nbsp;prototype</strong> — <em>UNAUDITED</em>. ' +
    'Keys are in a browser <b>software keystore</b>, not hardware, not a StrongBox, not a Secure Enclave. ' +
    'BLOCH is worthless by design and is not a security. It moves no real funds unless labelled.</p>';
  assert.deepEqual(checkScreen(jsx), []);
});

test('e2e: GOOD dist exits 0', () => {
  const dist = mkdist({ home: GOOD, send: GOOD, settings: GOOD });
  const r = runCli(dist);
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /honesty gate OK: 3 screen/);
});

test('e2e: BAD dist (one screen drops a phrase) exits 1 and names the screen', () => {
  const weakened = HONESTY_COPY.replace('and is not a security', '');
  const dist = mkdist({ home: GOOD, send: weakened, settings: GOOD });
  const r = runCli(dist);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /screen "send".*MISSING/s);
  assert.match(r.stderr, /not a security/i);
});

test('e2e: every single dropped disclosure fails the build (per-phrase coverage)', () => {
  const drops = [
    ['reference prototype', /reference[\s‑–—-]*prototype/gi],
    ['UNAUDITED', /unaudited/gi],
    ['software keystore', /software keystore/gi],
    ['not a security', /is not a security/gi],
    ['moves no real funds', /moves no real funds unless labelled/gi],
  ];
  for (const [name, re] of drops) {
    const broken = HONESTY_COPY.replace(re, 'XXX');
    const dist = mkdist({ home: GOOD, broken });
    const r = runCli(dist);
    assert.equal(r.code, 1, `dropping "${name}" should fail; stderr=${r.stderr}`);
    assert.match(r.stderr, /screen "broken".*MISSING/s, `expected "broken" flagged when dropping ${name}`);
  }
});

test('e2e: fail-closed when manifest is missing', () => {
  const dist = mkdist({ home: GOOD }, { manifest: false });
  const r = runCli(dist);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /manifest not found/i);
});

test('e2e: fail-closed when manifest lists no screens', () => {
  const dist = mkdist({}, { manifestBody: JSON.stringify({ screens: [] }) });
  const r = runCli(dist);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /no screens/i);
});

test('e2e: fail-closed when a manifest screen file is absent', () => {
  const dist = mkdist({ home: GOOD }, { manifestBody: JSON.stringify({ screens: [{ id: 'ghost', file: 'assets/ghost.js' }] }) });
  const r = runCli(dist);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /screen "ghost".*no built file resolved/s);
});

test('e2e: fail-closed when dist does not exist', () => {
  const r = runCli(path.join(os.tmpdir(), 'does-not-exist-' + Date.now()));
  assert.equal(r.code, 1);
  assert.match(r.stderr, /dist not found/i);
});

test('e2e: fail-closed on invalid JSON manifest', () => {
  const dist = mkdist({ home: GOOD }, { manifestBody: '{ not json' });
  const r = runCli(dist);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /not valid JSON/i);
});

test('e2e: glob resolution + code-split copy passes', () => {
  // Screen split across two chunks; the honesty copy lives in only ONE of them.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'honesty-glob-'));
  fs.mkdirSync(path.join(dir, 'assets'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'assets', 'send-a1b2.js'), 'export const view = () => "form";');
  fs.writeFileSync(path.join(dir, 'assets', 'send-c3d4.js'), `export const banner = ${JSON.stringify(GOOD)};`);
  fs.writeFileSync(path.join(dir, 'honesty-manifest.json'), JSON.stringify({ screens: [{ id: 'send', glob: 'assets/send-*.js' }] }));
  const r = runCli(dir);
  assert.equal(r.code, 0, r.stderr);
});

test('e2e: glob resolving to zero files fails closed', () => {
  const dist = mkdist({}, { manifestBody: JSON.stringify({ screens: [{ id: 'send', glob: 'assets/send-*.js' }] }) });
  const r = runCli(dist);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /no built file resolved/);
});

test('e2e: shipped example-dist passes (contract stays green)', () => {
  const exampleDist = path.join(HERE, 'example-dist');
  const r = runCli(exampleDist);
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /honesty gate OK/);
});

test('unit: run() returns structured result without spawning', () => {
  const dist = mkdist({ home: GOOD });
  const res = run(dist, null);
  assert.equal(res.ok, true);
  assert.equal(res.screensChecked, 1);
  assert.deepEqual(res.errors, []);
});
