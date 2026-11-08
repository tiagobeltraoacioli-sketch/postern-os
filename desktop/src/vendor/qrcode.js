// SPDX-License-Identifier: MIT OR Apache-2.0
// qrcode.js — a tiny, self-contained QR Code encoder (byte mode, ECC level L,
// versions 1..6). No dependencies, no network — it must run under the desktop's
// strict CSP (script-src 'self'; no CDN). Enough for the pairing anchor payload
// (~a hundred bytes); larger inputs throw and the caller falls back to text.
//
// Scope, on purpose: byte mode only; ECC level L; versions 1..6 (so NO version-
// information blocks, which begin at v7). Reed-Solomon over GF(256), the 8
// standard data masks with penalty scoring, and the 15-bit BCH format string.
// This is a rendering convenience for a local ceremony, not a cryptographic part.
(function () {
  "use strict";

  // ── GF(256) with primitive polynomial 0x11d ──────────────────────────────
  const EXP = new Uint8Array(512);
  const LOG = new Uint8Array(256);
  (function initGF() {
    let x = 1;
    for (let i = 0; i < 255; i++) {
      EXP[i] = x;
      LOG[x] = i;
      x <<= 1;
      if (x & 0x100) x ^= 0x11d;
    }
    for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  })();
  const gfMul = (a, b) => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]);

  // Reed-Solomon generator polynomial for `degree` EC codewords.
  function rsGenPoly(degree) {
    let poly = [1];
    for (let d = 0; d < degree; d++) {
      const next = new Array(poly.length + 1).fill(0);
      for (let i = 0; i < poly.length; i++) {
        next[i] ^= poly[i];
        next[i + 1] ^= gfMul(poly[i], EXP[d]);
      }
      poly = next;
    }
    return poly;
  }

  // EC codewords for one data block.
  function rsEncode(data, ecLen) {
    const gen = rsGenPoly(ecLen);
    const res = new Uint8Array(data.length + ecLen);
    res.set(data);
    for (let i = 0; i < data.length; i++) {
      const factor = res[i];
      if (factor !== 0) {
        for (let j = 0; j < gen.length; j++) res[i + j] ^= gfMul(gen[j], factor);
      }
    }
    return res.slice(data.length);
  }

  // ── version tables, level L, v1..6 ───────────────────────────────────────
  //                        v1   v2   v3   v4   v5   v6
  const DATA_CW  = [null, 19,  34,  55,  80, 108, 136];
  const EC_CW    = [null,  7,  10,  15,  20,  26,  18]; // per block
  const N_BLOCKS = [null,  1,   1,   1,   1,   1,   2];
  const REMAIN   = [null,  0,   7,   7,   7,   7,   7]; // remainder bits
  const ALIGN    = [null, null, 18, 22, 26, 30, 34];   // single alignment center (v2..6)
  const MAX_VERSION = 6;

  function chooseVersion(byteLen) {
    for (let v = 1; v <= MAX_VERSION; v++) {
      // mode(4) + count(8) + data(8·len) + terminator(≤4) must fit.
      const needBits = 4 + 8 + 8 * byteLen;
      if (needBits <= DATA_CW[v] * 8) return v;
    }
    throw new Error("payload too large for the built-in QR encoder (max version 6)");
  }

  // ── bitstream → codewords ────────────────────────────────────────────────
  function encodeData(bytes, version) {
    const totalDataCw = DATA_CW[version];
    const bits = [];
    const push = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1); };
    push(0b0100, 4);           // byte mode
    push(bytes.length, 8);     // count (8-bit for v1..9)
    for (const b of bytes) push(b, 8);
    // terminator
    const cap = totalDataCw * 8;
    for (let i = 0; i < 4 && bits.length < cap; i++) bits.push(0);
    while (bits.length % 8 !== 0) bits.push(0);
    const cw = [];
    for (let i = 0; i < bits.length; i += 8) {
      let byte = 0;
      for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i + j];
      cw.push(byte);
    }
    const PADS = [0xec, 0x11];
    let p = 0;
    while (cw.length < totalDataCw) cw.push(PADS[p++ % 2]);
    return cw;
  }

  // Split into blocks, RS-encode, interleave data then EC (all blocks equal for v1..6).
  function buildCodewords(dataCw, version) {
    const nb = N_BLOCKS[version];
    const ecLen = EC_CW[version];
    const per = dataCw.length / nb;
    const dataBlocks = [];
    const ecBlocks = [];
    for (let b = 0; b < nb; b++) {
      const blk = dataCw.slice(b * per, (b + 1) * per);
      dataBlocks.push(blk);
      ecBlocks.push(rsEncode(Uint8Array.from(blk), ecLen));
    }
    const out = [];
    for (let i = 0; i < per; i++) for (let b = 0; b < nb; b++) out.push(dataBlocks[b][i]);
    for (let i = 0; i < ecLen; i++) for (let b = 0; b < nb; b++) out.push(ecBlocks[b][i]);
    return out;
  }

  // ── matrix construction ──────────────────────────────────────────────────
  function newMatrix(size) {
    const m = [];
    for (let r = 0; r < size; r++) m.push(new Array(size).fill(null));
    return m;
  }

  function placeFinder(m, r, c) {
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) {
        const rr = r + dr, cc = c + dc;
        if (rr < 0 || cc < 0 || rr >= m.length || cc >= m.length) continue;
        const inner = dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6;
        let dark = false;
        if (inner) {
          const ring = dr === 0 || dr === 6 || dc === 0 || dc === 6;
          const core = dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4;
          dark = ring || core;
        }
        m[rr][cc] = dark ? 1 : 0; // separators fall out as the 0-ring
      }
    }
  }

  function placeAlignment(m, cr, cc) {
    for (let dr = -2; dr <= 2; dr++) {
      for (let dc = -2; dc <= 2; dc++) {
        const ring = Math.max(Math.abs(dr), Math.abs(dc));
        m[cr + dr][cc + dc] = ring === 1 ? 0 : 1;
      }
    }
  }

  function reserveFormat(m) {
    const size = m.length;
    // mark (as reserved, value 0 for now) the format-info + version areas.
    for (let i = 0; i <= 8; i++) {
      if (m[8][i] === null) m[8][i] = 0;
      if (m[i][8] === null) m[i][8] = 0;
    }
    for (let i = 0; i < 8; i++) {
      if (m[8][size - 1 - i] === null) m[8][size - 1 - i] = 0;
      if (m[size - 1 - i][8] === null) m[size - 1 - i][8] = 0;
    }
    m[size - 8][8] = 1; // the always-dark module
  }

  function buildTemplate(version) {
    const size = 17 + 4 * version;
    const m = newMatrix(size);
    placeFinder(m, 0, 0);
    placeFinder(m, 0, size - 7);
    placeFinder(m, size - 7, 0);
    // timing patterns
    for (let i = 8; i < size - 8; i++) {
      if (m[6][i] === null) m[6][i] = i % 2 === 0 ? 1 : 0;
      if (m[i][6] === null) m[i][6] = i % 2 === 0 ? 1 : 0;
    }
    if (ALIGN[version]) placeAlignment(m, ALIGN[version], ALIGN[version]);
    reserveFormat(m);
    return m;
  }

  // Which cells are free for data (null in the *template*, before format bits).
  function dataMask(version) {
    const t = buildTemplate(version);
    const size = t.length;
    const free = [];
    for (let r = 0; r < size; r++) free.push(t[r].map((v) => v === null));
    return { template: t, free, size };
  }

  function placeBits(matrix, free, codewords, version) {
    const size = matrix.length;
    const bits = [];
    for (const cw of codewords) for (let i = 7; i >= 0; i--) bits.push((cw >> i) & 1);
    for (let i = 0; i < REMAIN[version]; i++) bits.push(0);
    let idx = 0;
    let upward = true;
    for (let col = size - 1; col > 0; col -= 2) {
      if (col === 6) col--; // skip the vertical timing column
      for (let k = 0; k < size; k++) {
        const row = upward ? size - 1 - k : k;
        for (let c = 0; c < 2; c++) {
          const cc = col - c;
          if (!free[row][cc]) continue;
          matrix[row][cc] = idx < bits.length ? bits[idx] : 0;
          idx++;
        }
      }
      upward = !upward;
    }
  }

  const MASKS = [
    (r, c) => (r + c) % 2 === 0,
    (r) => r % 2 === 0,
    (_, c) => c % 3 === 0,
    (r, c) => (r + c) % 3 === 0,
    (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
    (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
    (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
    (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
  ];

  function applyMask(matrix, free, maskFn) {
    const size = matrix.length;
    const out = matrix.map((row) => row.slice());
    for (let r = 0; r < size; r++)
      for (let c = 0; c < size; c++)
        if (free[r][c] && maskFn(r, c)) out[r][c] ^= 1;
    return out;
  }

  // 15-bit BCH format string for level L (01) + mask.
  function formatBits(mask) {
    let data = (0b01 << 3) | mask;
    let rem = data << 10;
    for (let i = 14; i >= 10; i--) if ((rem >> i) & 1) rem ^= 0x537 << (i - 10);
    const bits = ((data << 10) | rem) ^ 0x5412;
    return bits & 0x7fff;
  }

  function placeFormat(matrix, mask) {
    const size = matrix.length;
    const bits = formatBits(mask);
    const get = (i) => (bits >> i) & 1;
    // around the top-left finder
    for (let i = 0; i <= 5; i++) matrix[8][i] = get(i);
    matrix[8][7] = get(6);
    matrix[8][8] = get(7);
    matrix[7][8] = get(8);
    for (let i = 9; i <= 14; i++) matrix[14 - i][8] = get(i);
    // the mirrored copy
    for (let i = 0; i <= 7; i++) matrix[size - 1 - i][8] = get(i);
    for (let i = 8; i <= 14; i++) matrix[8][size - 15 + i] = get(i);
    matrix[size - 8][8] = 1; // always-dark
  }

  // ── penalty scoring (choose the least-bad mask) ──────────────────────────
  function penalty(m) {
    const n = m.length;
    let score = 0;
    // rule 1: runs of ≥5 same-color in rows and columns
    const run = (get) => {
      let s = 0;
      for (let a = 0; a < n; a++) {
        let last = -1, len = 0;
        for (let b = 0; b < n; b++) {
          const v = get(a, b);
          if (v === last) { len++; if (len === 5) s += 3; else if (len > 5) s += 1; }
          else { last = v; len = 1; }
        }
      }
      return s;
    };
    score += run((a, b) => m[a][b]) + run((a, b) => m[b][a]);
    // rule 2: 2×2 same-color blocks
    for (let r = 0; r < n - 1; r++)
      for (let c = 0; c < n - 1; c++)
        if (m[r][c] === m[r][c + 1] && m[r][c] === m[r + 1][c] && m[r][c] === m[r + 1][c + 1]) score += 3;
    // rule 3: finder-like 1:1:3:1:1 patterns
    const pat1 = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
    const pat2 = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1];
    const match = (get, a, b) => {
      for (const pat of [pat1, pat2]) {
        let ok = true;
        for (let k = 0; k < 11; k++) if (get(a, b + k) !== pat[k]) { ok = false; break; }
        if (ok) return true;
      }
      return false;
    };
    for (let r = 0; r < n; r++)
      for (let c = 0; c <= n - 11; c++) {
        if (match((a, b) => m[a][b], r, c)) score += 40;
        if (match((a, b) => m[b][a], r, c)) score += 40;
      }
    // rule 4: dark-module balance
    let dark = 0;
    for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) dark += m[r][c];
    const pct = (dark * 100) / (n * n);
    score += Math.floor(Math.abs(pct - 50) / 5) * 10;
    return score;
  }

  // ── public API ───────────────────────────────────────────────────────────
  // encode(text) → { size, modules: boolean[][] }
  function encode(text) {
    const bytes = Array.from(new TextEncoder().encode(text));
    const version = chooseVersion(bytes.length);
    const dataCw = encodeData(bytes, version);
    const codewords = buildCodewords(dataCw, version);
    const { free } = dataMask(version);
    const base = buildTemplate(version);
    placeBits(base, free, codewords, version);

    let best = null;
    for (let mask = 0; mask < 8; mask++) {
      const masked = applyMask(base, free, MASKS[mask]);
      placeFormat(masked, mask);
      const p = penalty(masked);
      if (!best || p < best.p) best = { p, matrix: masked };
    }
    return { size: best.matrix.length, modules: best.matrix.map((row) => row.map((v) => v === 1)) };
  }

  // Render into an SVG string (crisp, theme-driven via currentColor).
  function toSVG(text, opts) {
    const o = opts || {};
    const quiet = o.quiet == null ? 4 : o.quiet;
    const { size, modules } = encode(text);
    const dim = size + quiet * 2;
    let rects = "";
    for (let r = 0; r < size; r++)
      for (let c = 0; c < size; c++)
        if (modules[r][c]) rects += `<rect x="${c + quiet}" y="${r + quiet}" width="1" height="1"/>`;
    return (
      `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${dim} ${dim}" ` +
      `shape-rendering="crispEdges" role="img" aria-label="Pairing QR code">` +
      `<rect x="0" y="0" width="${dim}" height="${dim}" fill="#ffffff"/>` +
      `<g fill="#000000">${rects}</g></svg>`
    );
  }

  window.PosternQR = { encode, toSVG, MAX_VERSION };
})();
