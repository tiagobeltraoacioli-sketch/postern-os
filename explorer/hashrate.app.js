/* Bloch Explorer — Hashrate dashboard (client-side, single-vantage estimate).
 *
 * Estimates NETWORK HASHRATE from the hashcash difficulty target (`bits`) and
 * block intervals reported by ONE node's JSON-RPC. It is an ESTIMATE, not a
 * measurement: work_per_block = 2^256 / (target+1); hashrate ≈ Σwork / Δtime.
 * At this chain's low hashrate the per-block signal is noisy — the SIS gate
 * (a difficulty-driven k-ramp, k=4 today) is a SEPARATE structural filter and
 * is NOT folded into this number. No
 * tracking; the only requests are the JSON-RPC POSTs to the endpoint you set.
 */
(function () {
  "use strict";

  const DEFAULT_RPCS = ['/api/rpc', 'http://127.0.0.1:16210/'];
  const DEFAULT_RPC = DEFAULT_RPCS[0];
  const LS_RPC = 'postern_explorer_rpc';
  const LS_WIN = 'postern_hashrate_window';

  const $ = (id) => document.getElementById(id);
  const rpcInput = $('rpc'), connEl = $('conn'), errEl = $('err'),
        statsEl = $('stats'), updEl = $('updated'), canvas = $('chart'),
        winInput = $('window'), autoEl = $('auto'), intEl = $('interval'),
        connectBtn = $('connect');

  let _storedRpc = localStorage.getItem(LS_RPC);
  if (_storedRpc && /blochv-node\.fly\.dev/.test(_storedRpc)) { _storedRpc = null; localStorage.removeItem(LS_RPC); }
  rpcInput.value = (_storedRpc || DEFAULT_RPC).trim();
  if (winInput) winInput.value = localStorage.getItem(LS_WIN) || '80';

  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const normEp = (e) => (e || '').trim().replace(/\/+$/, '');
  const endpoint = () => normEp(rpcInput.value);
  const commas = (n) => (n == null || !isFinite(n) ? '—' : Number(n).toLocaleString('en-US'));

  let reqId = 0;
  async function rpc(method, params = [], timeoutMs = 13000) {
    const ep = endpoint();
    if (!ep) throw new Error('No RPC endpoint set.');
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), timeoutMs);
    try {
      const res = await fetch(ep, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: ++reqId, method, params }),
        signal: ctl.signal, mode: 'cors', credentials: 'omit',
      });
      if (!res.ok) throw new Error('HTTP ' + res.status + ' ' + res.statusText);
      const j = await res.json();
      if (j && j.error) throw new Error(j.error.message || 'RPC error');
      return j ? j.result : null;
    } finally { clearTimeout(t); }
  }

  /* ── bits (compact nBits, 32-bit) → target → expected work ──────────── */
  function bitsToTarget(bits) {
    bits = bits >>> 0;
    const exp = bits >>> 24;
    const mant = BigInt(bits & 0x007fffff);
    return exp <= 3 ? (mant >> BigInt(8 * (3 - exp))) : (mant << BigInt(8 * (exp - 3)));
  }
  const TWO256 = 1n << 256n;
  const K_DEFAULT = 4; // Module-SIS gate coefficients — difficulty-driven k-ramp, k=4 today (read live when the RPC exposes it)
  // Expected candidate EVALUATIONS to mine a block: a candidate must clear BOTH
  // the hashcash target AND the Module-SIS gate. hashcash ≈ 2^256/(target+1);
  // the SIS gate constrains k residual coeffs with β=q/16 → P≈1/8 per coeff, so
  // it is ~8^k = 2^(3k) rarer. Folding it in is what makes the number meaningful
  // for Bloch — the hashcash difficulty alone is deliberately loose.
  function hashcashWork(bits) {
    const t = bitsToTarget(bits);
    return t <= 0n ? 0n : TWO256 / (t + 1n);
  }
  function workOf(bits, k) {
    const hc = hashcashWork(bits);
    return hc <= 0n ? 0n : (hc << BigInt(3 * ((k | 0) || K_DEFAULT))); // × 8^k for the SIS gate
  }

  function fmtHs(x) {
    if (!isFinite(x) || x <= 0) return '—';
    const u = ['H/s', 'kH/s', 'MH/s', 'GH/s', 'TH/s', 'PH/s', 'EH/s'];
    let i = 0; while (x >= 1000 && i < u.length - 1) { x /= 1000; i++; }
    return x.toFixed(x < 10 ? 2 : x < 100 ? 1 : 0) + ' ' + u[i];
  }
  function fmtDur(s) {
    if (!isFinite(s) || s <= 0) return '—';
    if (s < 90) return s.toFixed(0) + ' s';
    if (s < 5400) return (s / 60).toFixed(1) + ' min';
    if (s < 172800) return (s / 3600).toFixed(1) + ' h';
    return (s / 86400).toFixed(1) + ' d';
  }

  /* ── analyze a window of blocks ─────────────────────────────────────── */
  function analyze(blocks, kSis) {
    const k = (kSis | 0) || K_DEFAULT;
    const bs = (blocks || [])
      .filter((b) => b && b.bits != null && b.timestamp != null)
      .sort((a, b) => a.height - b.height);
    if (bs.length < 3) return null;
    const pts = []; // instantaneous per-interval
    for (let i = 1; i < bs.length; i++) {
      const dt = bs[i].timestamp - bs[i - 1].timestamp;
      if (dt <= 0) continue; // skip out-of-order / same-second timestamps
      pts.push({ height: bs[i].height, time: bs[i].timestamp, hs: Number(workOf(bs[i].bits, k)) / dt });
    }
    if (pts.length < 2) return null;
    let totalW = 0n;
    for (let i = 1; i < bs.length; i++) totalW += workOf(bs[i].bits, k);
    const span = bs[bs.length - 1].timestamp - bs[0].timestamp;
    const overall = span > 0 ? Number(totalW) / span : NaN;
    const avgInterval = span > 0 ? span / (bs.length - 1) : NaN;
    const sm = Math.min(8, Math.max(3, Math.floor(pts.length / 6)));
    const roll = pts.map((p, i) => {
      const slice = pts.slice(Math.max(0, i - sm + 1), i + 1);
      return { height: p.height, time: p.time, hs: slice.reduce((s, x) => s + x.hs, 0) / slice.length };
    });
    return {
      pts, roll, overall, avgInterval, span, count: bs.length, smoothK: sm, kSis: k,
      latestBits: bs[bs.length - 1].bits, latestHeight: bs[bs.length - 1].height,
      firstHeight: bs[0].height,
    };
  }

  /* ── stats cards ────────────────────────────────────────────────────── */
  function renderStats(a) {
    if (!a) { statsEl.innerHTML = ''; return; }
    const latest = a.roll[a.roll.length - 1] ? a.roll[a.roll.length - 1].hs : NaN;
    const diffHex = '0x' + (a.latestBits >>> 0).toString(16).padStart(8, '0');
    const card = (k, v, sub, hero) =>
      `<div class="stat${hero ? ' hero-num' : ''}"><div class="k">${k}</div><div class="v">${v}</div>${sub ? `<div class="sub">${sub}</div>` : ''}</div>`;
    statsEl.innerHTML =
      card('Estimated hashrate', esc(fmtHs(a.overall)), `candidate evals/s · folds the k=${a.kSis} SIS gate · mean over ${a.count} blocks`, true) +
      card('Latest (smoothed)', esc(fmtHs(latest)), `rolling ${a.smoothK}-interval mean`) +
      card('Avg block interval', esc(fmtDur(a.avgInterval)), `across the window (~30 s target)`) +
      card('SIS gate', `k = ${a.kSis}`, `each candidate ~8^${a.kSis} rarer (&times;2^${3 * a.kSis})`) +
      card('Hashcash difficulty', esc(diffHex), `bits at block ${commas(a.latestHeight)}`) +
      card('Window', `${commas(a.firstHeight)}&ndash;${commas(a.latestHeight)}`, `${esc(fmtDur(a.span))} of chain time`);
  }

  /* ── canvas chart (pure 2D, DPR-aware, theme-driven) ────────────────── */
  function cssVar(name, fallback) {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback;
  }
  let lastA = null;
  function draw(a) {
    lastA = a;
    if (!canvas) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const cssW = canvas.clientWidth || 800, cssH = canvas.clientHeight || 320;
    canvas.width = Math.round(cssW * dpr); canvas.height = Math.round(cssH * dpr);
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cssW, cssH);

    const brass = cssVar('--brass', '#b8860b'), brassHi = cssVar('--brass-hi', '#d9a94a');
    const line = cssVar('--border', '#2c2823'), muted = cssVar('--muted', '#6f695d');
    const dim = cssVar('--text-dim', '#9c968a');
    ctx.font = "11px ui-monospace, Menlo, monospace";

    if (!a || a.roll.length < 2) {
      ctx.fillStyle = muted; ctx.textAlign = 'center';
      ctx.fillText('Connect to a node to estimate hashrate.', cssW / 2, cssH / 2);
      return;
    }
    const padL = 62, padR = 14, padT = 14, padB = 26;
    const W = cssW - padL - padR, H = cssH - padT - padB;
    const series = a.roll, raw = a.pts;
    const xs = series.map((p) => p.height);
    const allHs = raw.map((p) => p.hs).concat(series.map((p) => p.hs));
    const minX = xs[0], maxX = xs[xs.length - 1];
    let maxY = Math.max.apply(null, allHs); if (!(maxY > 0)) maxY = 1;
    maxY *= 1.12;
    const X = (h) => padL + (maxX === minX ? W / 2 : ((h - minX) / (maxX - minX)) * W);
    const Y = (v) => padT + H - (Math.max(0, v) / maxY) * H;

    // grid + y labels
    ctx.strokeStyle = line; ctx.fillStyle = muted; ctx.lineWidth = 1; ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
    for (let i = 0; i <= 4; i++) {
      const gy = padT + (H / 4) * i, val = maxY * (1 - i / 4);
      ctx.beginPath(); ctx.moveTo(padL, gy + 0.5); ctx.lineTo(padL + W, gy + 0.5); ctx.stroke();
      ctx.fillText(fmtHs(val), padL - 8, gy);
    }
    // x labels (first / mid / last height)
    ctx.textAlign = 'center'; ctx.textBaseline = 'top';
    [minX, Math.round((minX + maxX) / 2), maxX].forEach((h) => ctx.fillText(commas(h), X(h), padT + H + 7));

    // faint raw points
    ctx.fillStyle = dim + '66';
    raw.forEach((p) => { ctx.beginPath(); ctx.arc(X(p.height), Y(p.hs), 1.4, 0, 7); ctx.fill(); });

    // area fill under the smoothed line
    ctx.beginPath();
    series.forEach((p, i) => { const x = X(p.height), y = Y(p.hs); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
    ctx.lineTo(X(maxX), padT + H); ctx.lineTo(X(minX), padT + H); ctx.closePath();
    const g = ctx.createLinearGradient(0, padT, 0, padT + H);
    g.addColorStop(0, brass + '3a'); g.addColorStop(1, brass + '05');
    ctx.fillStyle = g; ctx.fill();

    // smoothed line
    ctx.beginPath();
    series.forEach((p, i) => { const x = X(p.height), y = Y(p.hs); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
    ctx.strokeStyle = brass; ctx.lineWidth = 2; ctx.lineJoin = 'round'; ctx.stroke();

    // emphasized endpoint
    const last = series[series.length - 1];
    ctx.fillStyle = brassHi; ctx.beginPath(); ctx.arc(X(last.height), Y(last.hs), 3.4, 0, 7); ctx.fill();
    ctx.strokeStyle = brassHi + '55'; ctx.lineWidth = 1;
    ctx.beginPath(); ctx.arc(X(last.height), Y(last.hs), 6.5, 0, 7); ctx.stroke();
  }

  /* ── connection + refresh loop ──────────────────────────────────────── */
  function setConn(cls, txt) { connEl.className = 'conn ' + cls; connEl.textContent = txt; }
  function showErr(cause, raw) {
    errEl.style.display = '';
    errEl.innerHTML = `<h3>Could not read the node</h3><p class="cause">${esc(cause)}</p>` +
      `<ul><li>Is the endpoint a reachable Bloch node RPC (JSON-RPC 2.0 over POST)?</li>` +
      `<li>From an HTTPS page, the node must be HTTPS and CORS-enabled; plain-HTTP is blocked as mixed content (localhost excepted).</li></ul>` +
      (raw ? `<p class="raw">${esc(raw)}</p>` : '');
  }
  const clearErr = () => { errEl.style.display = 'none'; errEl.innerHTML = ''; };

  let timer = null, inFlight = false;
  function windowSize() {
    let n = parseInt(winInput && winInput.value, 10);
    if (!isFinite(n)) n = 80;
    return Math.max(10, Math.min(500, n));
  }

  async function refresh() {
    if (inFlight) return; inFlight = true;
    setConn('warn', 'reading…');
    try {
      const n = windowSize();
      const [blocks, k] = await Promise.all([
        rpc('getrecentblocks', [n]),
        // best-effort: read the live SIS gate width (the k-ramp); fall back to the current floor k=4
        rpc('getblocktemplate').then((r) => (r && (r.residual_coeffs | 0)) || K_DEFAULT).catch(() => K_DEFAULT),
      ]);
      const a = analyze(blocks, k);
      if (!a) {
        setConn('warn', 'thin data');
        showErr('The node returned too few blocks (with usable timestamps/bits) to estimate hashrate yet.', Array.isArray(blocks) ? blocks.length + ' block(s)' : String(blocks));
        renderStats(null); draw(null);
      } else {
        clearErr(); setConn('ok', 'live');
        renderStats(a); draw(a);
        updEl.textContent = 'Updated ' + new Date().toLocaleTimeString() + ' · ' +
          a.count + ' blocks from ' + esc(endpoint());
      }
    } catch (e) {
      setConn('err', 'error');
      showErr(e && e.name === 'AbortError' ? 'The request timed out.' : (e && e.message) || 'Request failed.', String(e));
    } finally { inFlight = false; }
  }

  function restart() {
    if (timer) { clearInterval(timer); timer = null; }
    if (autoEl && autoEl.checked) {
      let s = parseInt(intEl && intEl.value, 10); if (!isFinite(s)) s = 15;
      s = Math.max(5, Math.min(600, s));
      timer = setInterval(refresh, s * 1000);
    }
  }

  function connect() {
    localStorage.setItem(LS_RPC, rpcInput.value.trim());
    if (winInput) localStorage.setItem(LS_WIN, String(windowSize()));
    refresh(); restart();
  }

  if (connectBtn) connectBtn.onclick = connect;
  rpcInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') connect(); });
  if (winInput) winInput.addEventListener('change', connect);
  if (autoEl) autoEl.addEventListener('change', restart);
  if (intEl) intEl.addEventListener('change', restart);
  let rt = null;
  window.addEventListener('resize', () => { clearTimeout(rt); rt = setTimeout(() => draw(lastA), 120); });

  // first paint
  refresh(); restart();
})();
