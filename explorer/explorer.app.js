'use strict';
/* Bloch Explorer — Postern Labs.
 * Inlined into explorer/index.html by explorer/build.js.
 * The ONLY network requests this page makes are JSON-RPC 2.0 POSTs to the
 * node endpoint the user configures. All node-supplied strings are escaped
 * before rendering. */
(function () {
  const $ = (s) => document.querySelector(s);
  const DASH = '—';
  /* A short BUNDLED fallback list so a single disposable-node outage does not
     blank the explorer (E1). The protocol is OWNERLESS — none of these is "the"
     node: the first is Postern's disposable demo node, the rest are honest
     fallbacks (a node you run locally on the standard RPC port 16210). A node
     the user types into the box ALWAYS wins and is never auto-swapped; the
     failover only ever hops between these bundled defaults, and only when the
     one currently in use stops answering. */
  const DEFAULT_RPCS = [
    '/api/rpc',
    'http://127.0.0.1:16210/',
  ];
  const DEFAULT_RPC = DEFAULT_RPCS[0];
  const LS_RPC = 'postern_explorer_rpc';

  const rpcInput = $('#rpc'), connEl = $('#conn'), errEl = $('#err');
  let timer = null, rpcId = 0, lastBlocks = [];
  let failedOver = null; // the primary endpoint we fell back FROM, for an honest note

  const normEp = (u) => String(u || '').trim().replace(/\/+$/, '');
  // Migrate visitors off the decommissioned Fly demo node to the same-origin proxy.
  let _storedRpc = localStorage.getItem(LS_RPC);
  if (_storedRpc && /blochv-node\.fly\.dev/.test(_storedRpc)) { _storedRpc = null; localStorage.removeItem(LS_RPC); }
  rpcInput.value = (_storedRpc || DEFAULT_RPC).trim();

  const endpoint = () => normEp(rpcInput.value);
  const DEFAULT_SET = DEFAULT_RPCS.map(normEp);
  const isDefaultEndpoint = (ep) => DEFAULT_SET.includes(normEp(ep));

  /* Per-call timeout: some heavier RPCs on public demo nodes hang; a bounded
     wait keeps auto-refresh from piling up requests. `rpcAt` targets an explicit
     endpoint (used by the bundled-default failover); `rpc` targets the active one. */
  async function rpcAt(ep, method, params = [], timeoutMs = 20000) {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), timeoutMs);
    try {
      const r = await fetch(normEp(ep) + '/', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }),
        referrerPolicy: 'no-referrer',
        signal: ctl.signal,
      });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const j = await r.json();
      if (j.error) throw new Error(typeof j.error === 'string' ? j.error : JSON.stringify(j.error));
      if (j.result && typeof j.result === 'object' && !Array.isArray(j.result) && j.result.error)
        throw new Error(String(j.result.error));
      return j.result;
    } finally { clearTimeout(t); }
  }
  const rpc = (method, params = [], timeoutMs = 20000) => rpcAt(endpoint(), method, params, timeoutMs);

  /* First live-contact call, with bundled-default failover. Try the active
     endpoint; if it fails AND the user is on a bundled default (not a node they
     typed), try the OTHER bundled defaults in order. The first that answers
     becomes the active node — visibly (the box updates) and honestly (a note
     says the primary was unreachable). A user-chosen endpoint is never swapped:
     its failure goes straight to the honest error UX. */
  async function connectPrimary() {
    const primary = endpoint();
    try {
      return await rpc('getnetworkinfo');
    } catch (e) {
      if (!isDefaultEndpoint(primary)) throw e;
      for (const cand of DEFAULT_SET) {
        if (normEp(cand) === normEp(primary)) continue;
        try {
          const net = await rpcAt(cand, 'getnetworkinfo');
          rpcInput.value = cand;
          localStorage.setItem(LS_RPC, cand);
          failedOver = primary;
          return net;
        } catch (_) { /* try the next bundled default */ }
      }
      throw e; // every bundled default is unreachable → the honest error UX
    }
  }

  /* ── wake/retry with exponential backoff ──────────────────────────────
     The default demo node is a Fly machine that AUTO-STOPS when idle and
     cold-starts (~2-5 s, sometimes more) on the first request after a sleep.
     The first RPC after idle therefore often times out or fails — that is
     NOT "node down", it is the machine waking up. So the page never shows a
     hard "not connected" on a first failure: it retries with exponential
     backoff (1 s → 2 s → 4 s → 8 s → 8 s → 8 s between attempts, each
     attempt itself bounded by the ~9 s per-request timeout — roughly
     30-40 s of patience in total) while showing an honest "waking /
     reconnecting" state, and only after the whole schedule fails does it
     fall through to the hard error UX. This promises nothing about uptime:
     the demo node stays a disposable convenience, not official infra. */
  const WAKE_DELAYS = [1000, 2000, 4000, 8000, 8000, 8000];
  const CANCELED = Symbol('canceled');
  let wakeGen = 0;          // bumping this cancels any in-flight wake loop
  let refreshing = false;   // prevents overlapping refresh cycles
  let queuedRefresh = false;
  let everConnected = false;
  let skipWait = null;      // resolver for the current backoff pause ("retry now")

  function wakeSleep(ms) {
    return new Promise((res) => {
      const t = setTimeout(() => { skipWait = null; res(); }, ms);
      skipWait = () => { clearTimeout(t); skipWait = null; res(); };
    });
  }
  function cancelWake() { wakeGen++; if (skipWait) skipWait(); }
  function restartRefresh() {
    cancelWake();
    if (refreshing) queuedRefresh = true; else refresh();
  }

  function showWaking(attempt, nextMs) {
    const reconnect = everConnected;
    setConn('warn', reconnect ? 'reconnecting…' : 'waking node…');
    errEl.className = 'warnpanel';       // amber, not red — this is not an error yet
    errEl.style.display = 'block';
    errEl.innerHTML = `<h3>${reconnect ? 'Connection dropped — reconnecting' : 'Waking the node…'}</h3>
      <p>No reply from <code>${esc(endpoint())}</code> yet. ${isDefaultEndpoint(endpoint())
        ? 'The demo node runs on a Fly machine that <strong>sleeps when idle</strong> and cold-starts on the first request (a few seconds, sometimes more) — a failed first call usually just means it is still waking up. It remains a <strong>disposable demo node</strong>, not official infrastructure; no uptime is promised.'
        : 'The node may still be starting up, or briefly unreachable.'}
      Retrying automatically — attempt ${attempt + 1} of ${WAKE_DELAYS.length + 1}, next try in ${Math.round(nextMs / 1000)}s.</p>
      <p style="margin-top:.6rem"><button class="btn small" id="retryNow" type="button">Retry now</button>
        <span class="small dim"> — if every retry fails, the honest error view (down vs CORS vs mixed content) follows.</span></p>`;
    const b = $('#retryNow');
    if (b) b.onclick = () => { if (skipWait) skipWait(); };
  }

  /* First contact with retry: only after the whole backoff schedule fails
     does the caller see the error (→ hard "not connected"). */
  async function connectWithRetry() {
    const gen = wakeGen;
    for (let i = 0; ; i++) {
      try {
        return await connectPrimary();
      } catch (e) {
        if (gen !== wakeGen) throw CANCELED;
        if (i >= WAKE_DELAYS.length) throw e;
        showWaking(i, WAKE_DELAYS[i]);
        await wakeSleep(WAKE_DELAYS[i]);
        if (gen !== wakeGen) throw CANCELED;
      }
    }
  }

  /* ── helpers ── */
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const commas = (n) => (n == null || isNaN(Number(n))) ? DASH : Number(n).toLocaleString('en-US');
  const short = (h, n = 10) => (h && typeof h === 'string') ? esc(h.slice(0, n)) + '…' + esc(h.slice(-4)) : DASH;
  const val = (v) => (v == null) ? DASH : esc(v);
  function ago(ts) {
    if (ts == null) return DASH;
    const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
    if (s < 60) return s + 's'; if (s < 3600) return Math.floor(s / 60) + 'm';
    if (s < 86400) return Math.floor(s / 3600) + 'h'; return Math.floor(s / 86400) + 'd';
  }
  function bytes(b) {
    if (b == null) return DASH;
    if (b < 1024) return b + ' B'; if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
    return (b / 1048576).toFixed(1) + ' MB';
  }
  function fmtBits(b) { // getblock returns "0x…" string; getrecentblocks returns a number
    if (b == null) return DASH;
    if (typeof b === 'string') return esc(b);
    return '0x' + (b >>> 0).toString(16).padStart(8, '0');
  }
  const fmtTs = (ts) => ts == null ? DASH : new Date(ts * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z/, ' UTC');
  const isHttpUrl = (u) => /^http:\/\//i.test(u || '');

  function setConn(state, txt) { connEl.className = 'conn' + (state ? ' ' + state : ''); connEl.textContent = txt; }
  const stat = (k, v, sub) => `<div class="stat"><div class="k">${k}</div><div class="v">${v}</div>${sub ? `<div class="sub">${sub}</div>` : ''}</div>`;

  /* copy-on-click for hashes */
  function copyText(text, el) {
    const done = () => { el.classList.add('copied'); setTimeout(() => el.classList.remove('copied'), 900); };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done).catch(() => {});
  }
  document.addEventListener('click', (e) => {
    const c = e.target.closest('[data-copy]');
    if (c) { e.stopPropagation(); copyText(c.getAttribute('data-copy'), c); }
  });
  const copyHash = (full, disp) => full
    ? `<span class="copyable hashlink" data-copy="${esc(full)}" title="click to copy · ${esc(full)}">${disp}</span>`
    : DASH;

  /* ── rendering ── */
  function renderStats(net, dag, count, blocks) {
    // Derive the tip height from getrecentblocks (the lightest, most reliable
    // RPC) so the headline still tracks the chain when getnetworkinfo /
    // getblockcount time out under a node's sync load, instead of freezing at
    // the last value.
    const tipFromBlocks = Array.isArray(blocks) && blocks.length
      ? Math.max(...blocks.map((b) => (b && b.height) || 0)) : null;
    const syncBadge = net.syncing
      ? '<span class="badge warn">syncing</span>'
      : '<span class="badge ok">synced</span>';
    $('#stats').innerHTML = [
      stat('Height', commas(net.blocks != null ? net.blocks : (count != null ? count : tipFromBlocks))),
      stat('Blue score', commas(net.blue_score)),
      stat('Peers', commas(net.peers), '<a href="network.html">single-vantage — network view →</a>'),
      stat('Mempool', commas(net.mempool) + ' <small>txs</small>'),
      stat('Sync', syncBadge),
      stat('DAG tips', dag ? commas(dag.tip_count) : DASH, dag && dag.k != null ? 'GhostDAG k=' + esc(dag.k) : ''),
      stat('Node reports network', val(net.network || net.chain),
        '<strong>unaudited mainnet beta · 51%-attackable · no value claim</strong> — whatever the node calls it'),
      stat('Protocol', val(net.net_protocol != null ? net.net_protocol : net.protocol),
        net.version ? 'node v' + esc(net.version) : ''),
    ].join('');
  }

  function renderBlocks(blocks) {
    lastBlocks = Array.isArray(blocks) ? blocks : [];
    const tb = $('#blocks tbody');
    tb.innerHTML = lastBlocks.map((b, i) => `<tr class="rowlink" data-i="${i}" title="open block detail">
      <td class="mono"><strong>${commas(b.height)}</strong></td>
      <td class="mono">${copyHash(b.hash, short(b.hash, 14))}</td>
      <td class="mono">${ago(b.timestamp)}</td>
      <td class="mono">${val(b.tx_count)}</td>
      <td class="mono">${bytes(b.size)}</td>
      <td class="mono">${fmtBits(b.bits)}</td>
    </tr>`).join('') || `<tr><td colspan="6"><div class="empty">no blocks returned by the node</div></td></tr>`;
    tb.querySelectorAll('tr[data-i]').forEach((tr) => {
      tr.onclick = () => { const b = lastBlocks[+tr.dataset.i]; if (b && b.hash) openBlockByHash(b.hash); };
    });
  }

  function renderSkeleton() {
    $('#stats').innerHTML = Array.from({ length: 8 }, () => stat('…', DASH)).join('');
    $('#blocks tbody').innerHTML = `<tr><td colspan="6"><div class="empty">waiting for a node connection…</div></td></tr>`;
  }

  /* ── error UX: honest about down vs CORS vs mixed content ── */
  function resetButton() {
    if (endpoint() === DEFAULT_RPC.replace(/\/+$/, '')) return '';
    return `<p style="margin-top:.8rem"><button class="btn small" id="useDefault" type="button">Use the Postern demo node (${esc(DEFAULT_RPC)})</button>
      <span class="small dim"> — disposable convenience, not official infrastructure.</span></p>`;
  }
  function wireResetButton() {
    const b = $('#useDefault');
    if (b) b.onclick = () => { rpcInput.value = DEFAULT_RPC; localStorage.setItem(LS_RPC, DEFAULT_RPC); everConnected = false; restartRefresh(); schedule(); };
  }
  const retryButton = () => `<p style="margin-top:.8rem"><button class="btn small" id="retryErr" type="button">Retry now</button>
      <span class="small dim"> — retries the same backoff schedule (the demo node may just need to wake again).</span></p>`;
  function wireRetryButton() {
    const b = $('#retryErr');
    if (b) b.onclick = restartRefresh;
  }
  function showError(e) {
    const msg = e && e.message ? e.message : String(e);
    const aborted = e && e.name === 'AbortError';
    const networkLike = aborted || (e && e.name === 'TypeError') || /failed to fetch|networkerror|load failed|network request failed/i.test(msg);
    const httpsPage = location.protocol === 'https:';
    const mixed = httpsPage && isHttpUrl(endpoint());
    errEl.className = 'errpanel';
    errEl.style.display = 'block';
    if (networkLike) {
      errEl.innerHTML = `<h3>Could not reach the node</h3>
        <p>The request to <code>${esc(endpoint() || '(empty)')}</code> ${aborted ? 'timed out' : 'failed before a reply arrived'}, and automatic retries with backoff (~30-40 s, enough to cover the demo node's cold start from sleep) failed too. A browser cannot see which of these it was, so all three are listed honestly:</p>
        <ul>
          <li><span class="cause">Node down or unreachable.</span> Confirm the node is running and its JSON-RPC is listening at that address.</li>
          <li><span class="cause">CORS blocked.</span> If the node does not send <code>Access-Control-Allow-Origin</code>, the browser silently blocks this page from reading the reply even when the node is up. Fixes: run the node behind a CORS-enabled reverse proxy, enable the node's CORS flag, or use the desktop (Tauri) build, which is not subject to browser CORS.</li>
          ${mixed ? '<li><span class="cause">Mixed content.</span> This page is served over HTTPS but the endpoint is <code>http://</code> — browsers block that. Use an HTTPS endpoint, or open the explorer over file:// or plain HTTP.</li>' : ''}
          <li><span class="cause">CSP.</span> This page's Content-Security-Policy allows HTTPS endpoints plus <code>http://127.0.0.1</code> / <code>localhost</code>; other plain-http hosts are blocked by design.</li>
        </ul>
        ${retryButton()}
        ${resetButton()}
        <p class="raw">raw error: ${esc(msg)}</p>`;
      wireRetryButton();
      wireResetButton();
    } else {
      errEl.innerHTML = `<h3>The node replied with an error</h3>
        <p>The endpoint is reachable but returned: <strong>${esc(msg)}</strong></p>
        ${retryButton()}
        <p class="raw">method support varies by node version — this explorer degrades to “${DASH}” for anything a node does not serve.</p>`;
      wireRetryButton();
    }
  }

  /* ── main refresh ──
     Doubles as the heartbeat: the auto-refresh interval re-runs this, and a
     failure mid-session goes back through the wake/backoff loop (an honest
     "reconnecting…" state) instead of jumping straight to a hard error.
     While reconnecting the last-seen data stays on screen; only a hard
     failure (whole backoff schedule exhausted) blanks it to the skeleton. */
  async function refresh() {
    if (refreshing) return; // a wake/backoff cycle is already running
    refreshing = true;
    try {
      if (!endpoint()) {
        setConn('err', 'no node set');
        renderSkeleton();
        errEl.className = 'errpanel';
        errEl.style.display = 'block';
        errEl.innerHTML = `<h3>No node configured</h3>
          <p>Enter a node's JSON-RPC endpoint above and press <strong>Connect</strong>. The protocol is ownerless — any node works.</p>${resetButton()}`;
        wireResetButton();
        return;
      }
      setConn('warn', everConnected ? 'reconnecting…' : 'connecting…');
      failedOver = null;
      let net;
      try {
        net = await connectWithRetry();
      } catch (e) {
        if (e === CANCELED) return; // superseded by a newer connect/retry
        setConn('err', 'not connected');
        renderSkeleton();
        showError(e);
        return;
      }
      errEl.style.display = 'none';
      errEl.className = 'errpanel';
      setConn('ok', 'connected');
      everConnected = true;
      const [dag, blocks, count] = await Promise.all([
        rpc('getdaginfo').catch(() => null),
        rpc('getrecentblocks', [20]).catch(() => []),
        net.blocks == null ? rpc('getblockcount').catch(() => null) : Promise.resolve(null),
      ]);
      try { renderStats(net, dag, count, blocks); } catch (e) { console.error('renderStats', e); }
      try { renderBlocks(blocks); } catch (e) { console.error('renderBlocks', e); }
      $('#updated').textContent = 'last updated ' + new Date().toLocaleTimeString()
        + (failedOver ? ' · primary node ' + failedOver + ' was unreachable — showing ' + endpoint() + ' instead' : '');
    } finally {
      refreshing = false;
      if (queuedRefresh) { queuedRefresh = false; refresh(); }
    }
  }

  /* ── block detail ── */
  const openBlockByHash = (hash) => openBlock(() => rpc('getblock', [hash, true]));
  const openBlockByHeight = (h) => openBlock(() => rpc('getblockbyheight', [h, true]));

  function closeDetail() { $('#detail').innerHTML = ''; }

  async function openBlock(fetcher) {
    const d = $('#detail');
    d.innerHTML = `<div class="detailpanel"><h3>Block <span class="badge warn">loading…</span></h3></div>`;
    d.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'nearest' });
    let b;
    try { b = await fetcher(); }
    catch (e) {
      d.innerHTML = `<div class="detailpanel"><h3>Block detail <button class="btn small close" id="dclose" type="button">close</button></h3>
        <p style="color:var(--danger)">RPC error: ${esc(e.message || e)}</p></div>`;
      $('#dclose').onclick = closeDetail;
      return;
    }
    const parents = (b.parents || []).map((p) => copyHash(p, short(p, 18))).join('<br>') || DASH;
    const txs = Array.isArray(b.transactions) ? b.transactions : null;
    const txids = Array.isArray(b.txids) ? b.txids : null;
    let txHtml = '';
    if (txs) {
      txHtml = txs.map((tx) => {
        const out = (tx.outputs || []).reduce((a, o) => a + (Number(o.value) || 0), 0);
        return `<div class="txbox">${copyHash(tx.txid, esc(tx.txid || DASH))}${tx.coinbase ? ' <span class="badge ok">coinbase</span>' : ''}
          <div class="meta">${(tx.inputs || []).length} in · ${(tx.outputs || []).length} out · ${(out / 1e8).toLocaleString('en-US', { maximumFractionDigits: 8 })} BLOCH out <span class="dim">(mainnet-beta units — no value claim, not a security)</span></div></div>`;
      }).join('');
    } else if (txids) {
      txHtml = txids.map((t) => `<div class="txbox">${copyHash(t, esc(t))}</div>`).join('');
    } else {
      txHtml = `<div class="txbox">${DASH}</div>`;
    }
    d.innerHTML = `<div class="detailpanel">
      <h3>Block ${commas(b.height)} <span class="badge warn">mainnet beta</span> <button class="btn small close" id="dclose" type="button">close</button></h3>
      <div class="kvlist">
        <div class="k">hash</div><div class="v">${copyHash(b.hash, esc(b.hash || DASH))}</div>
        <div class="k">height</div><div class="v">${commas(b.height)}</div>
        <div class="k">blue_score</div><div class="v">${commas(b.blue_score)}</div>
        <div class="k">timestamp</div><div class="v">${fmtTs(b.timestamp)} <span class="dim">(${ago(b.timestamp)} ago)</span></div>
        <div class="k">bits</div><div class="v">${fmtBits(b.bits)}</div>
        <div class="k">nonce</div><div class="v">${val(b.nonce)}</div>
        <div class="k">merkle_root</div><div class="v">${copyHash(b.merkle_root, esc(b.merkle_root || DASH))}</div>
        <div class="k">size</div><div class="v">${bytes(b.size)}</div>
        <div class="k">tx_count</div><div class="v">${val(b.tx_count)}</div>
        <div class="k">parents</div><div class="v">${parents}</div>
        <div class="k">SIS witness</div><div class="v">${Array.isArray(b.pow_solution) ? commas(b.pow_solution.length) + ' coefficients' : DASH + ' <span class="dim">(not exposed by the node RPC — shown honestly, not faked)</span>'}</div>
      </div>
      <h3 style="margin-top:1.1rem">Transactions <span class="badge">${txs ? txs.length : (txids ? txids.length : 0)}</span></h3>
      ${txHtml}</div>`;
    $('#dclose').onclick = closeDetail;
  }

  $('#go').onclick = () => {
    const q = $('#q').value.trim().replace(/^0x/, '');
    if (!q) return;
    if (/^\d+$/.test(q)) openBlockByHeight(parseInt(q, 10));
    else if (/^[0-9a-fA-F]{64}$/.test(q)) openBlockByHash(q.toLowerCase());
    else {
      $('#detail').innerHTML = `<div class="detailpanel"><h3>Block lookup <button class="btn small close" id="dclose" type="button">close</button></h3>
        <p style="color:var(--danger)">Enter a decimal height or a 64-character hex block hash.</p></div>`;
      $('#dclose').onclick = closeDetail;
    }
  };
  $('#q').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#go').click(); });

  /* ── address lookup ── */
  async function checkAddress() {
    const addr = $('#qaddr').value.trim();
    const box = $('#addrinfo');
    if (!addr) { box.innerHTML = ''; return; }
    if (!/^bloch1[a-z0-9]+$/i.test(addr)) {
      box.innerHTML = `<div class="errpanel" style="margin-top:1rem"><h3>Not a bloch address</h3><p>Enter a bloch1q… / bloch1t… address.</p></div>`;
      return;
    }
    box.innerHTML = `<div class="statgrid">${stat('Address', short(addr, 14), 'looking up… — pool/founder addresses with many UTXOs can take ~20s')}</div>`;
    try {
      // getaddressinfo is O(UTXOs) on the node: the founder/pool address has
      // ~390k UTXOs and takes ~16s to sum, so give address lookups a 30s budget.
      // The default 9s was aborting mid-request and surfacing "Lookup failed".
      const r = await rpc('getaddressinfo', [addr], 30000);
      box.innerHTML = `<div class="statgrid">
        ${stat('Balance', commas(r.balance_bloch) + ' <small>BLOCH</small>', 'mainnet-beta units — no value claim, not a security')}
        ${stat('Base units', commas(r.balance_sats), 'approximate for very large balances — base units exceed JavaScript\'s 2^53 exact-integer range')}
        ${stat('UTXOs', commas(r.utxo_count))}
        ${stat('Pool role', val(r.pool_role))}
        ${stat('Pending in / out', commas(r.pending_incoming || 0) + ' / ' + commas(r.pending_outgoing || 0))}
      </div>`;
    } catch (e) {
      box.innerHTML = `<div class="errpanel" style="margin-top:1rem"><h3>Lookup failed</h3><p>${esc(short(addr, 16))}: ${esc(e.message || String(e))}</p></div>`;
    }
  }
  $('#goaddr').onclick = checkAddress;
  $('#qaddr').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#goaddr').click(); });

  /* ── scheduling ── */
  function schedule() {
    if (timer) clearInterval(timer);
    if ($('#auto').checked && endpoint()) {
      const s = Math.max(5, parseInt($('#interval').value, 10) || 12);
      timer = setInterval(() => { if (!document.hidden) refresh(); }, s * 1000);
    }
  }
  $('#connect').onclick = () => {
    localStorage.setItem(LS_RPC, rpcInput.value.trim());
    everConnected = false; // fresh endpoint → "connecting"/"waking", not "reconnecting"
    restartRefresh();
    schedule();
  };
  $('#auto').onchange = schedule;
  $('#interval').onchange = schedule;
  rpcInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#connect').click(); });

  renderSkeleton();
  refresh();
  schedule();
})();
