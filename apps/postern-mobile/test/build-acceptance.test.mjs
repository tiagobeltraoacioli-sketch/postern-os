// Postern Mobile — build acceptance (node --test).
//
// Machine-checks the SHIPPED build against the item's acceptance criteria:
//   • dist/index.html exists, plus hashed same-origin assets/*.js and *.css.
//   • no external origins (no `https?://`) anywhere in dist/*.html or dist/assets.
//   • every <script> in dist/index.html is `type="module"` with a same-origin
//     assets/ src — NO inline script (no code block inside a <script> tag).
//
// Runs `vite build` itself (idempotent) so the test is self-contained.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const dist = join(root, 'dist');
const APP_BASE = '/apps/postern-mobile/';

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

test('build produces a self-contained same-origin dist/', () => {
  // Build (fresh) — the acceptance harness must not depend on a prior build.
  execFileSync('npx', ['vite', 'build'], { cwd: root, stdio: 'inherit' });

  // 1. index.html + hashed assets/*.js|*.css exist.
  const indexPath = join(dist, 'index.html');
  assert.ok(existsSync(indexPath), 'dist/index.html exists');

  const assetsDir = join(dist, 'assets');
  assert.ok(existsSync(assetsDir), 'dist/assets exists');
  const assetFiles = readdirSync(assetsDir);
  const jsFiles = assetFiles.filter((f) => /-[A-Za-z0-9_-]+\.js$/.test(f));
  const cssFiles = assetFiles.filter((f) => /-[A-Za-z0-9_-]+\.css$/.test(f));
  assert.ok(jsFiles.length >= 1, `hashed assets/*.js present (${jsFiles.join(', ')})`);
  assert.ok(cssFiles.length >= 1, `hashed assets/*.css present (${cssFiles.join(', ')})`);

  // 2. No external origins anywhere in shipped html + assets.
  const scanned = [indexPath, ...walk(assetsDir)];
  for (const f of scanned) {
    const body = readFileSync(f, 'utf8');
    const m = body.match(/https?:\/\/[^\s"'`)]+/);
    assert.equal(m, null, `no external origin in ${f} (found ${m && m[0]})`);
  }

  // 3. Every <script> is type=module + same-origin assets/ src, none inline.
  const html = readFileSync(indexPath, 'utf8');
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
  assert.ok(scripts.length >= 1, 'index.html has at least one <script>');
  for (const [, attrs, inner] of scripts) {
    assert.equal(inner.trim(), '', 'no inline script body');
    assert.match(attrs, /type="module"/, 'script is type=module');
    const srcMatch = attrs.match(/\ssrc="([^"]+)"/);
    assert.ok(srcMatch, 'script has a src (external, not inline)');
    const src = srcMatch[1];
    assert.ok(
      src.startsWith(`${APP_BASE}assets/`) || src.startsWith('./assets/') || src.startsWith('assets/'),
      `script src is a same-origin assets/ path: ${src}`,
    );
    assert.ok(!/^https?:\/\//.test(src), `script src is not external: ${src}`);
  }

  // 4. Any modulepreload links must also be same-origin (no inline polyfill).
  assert.ok(!/<script\b(?![^>]*\ssrc=)/i.test(html), 'no <script> without a src (no inline polyfill)');
});
