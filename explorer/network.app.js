'use strict';
/* Bloch Network page — Postern Labs.
 * Inlined into explorer/network.html by explorer/build.js.
 *
 * Honesty contract of this page:
 *   - every peer count shown is what ONE node reports about ITS OWN
 *     connections (getnetworkinfo.peers / getpeers) — a single vantage
 *     point, never a global crawl or "network size";
 *   - 0 peers is displayed as 0, with an explanation, never faked;
 *   - unreachable nodes are reported as such, with the honest note that a
 *     browser cannot distinguish "node down" from "CORS blocked".
 * The ONLY network requests are JSON-RPC 2.0 POSTs to user-configured
 * endpoints. All node-supplied strings are escaped before rendering. */
(function () {
  const $ = (s) => document.querySelector(s);
  const DASH = '—';
  /* Bundled fallback list — same rationale as the explorer page (E1): one
     disposable-node outage must not blank the primary tiles. The protocol is
     ownerless; the first is Postern's disposable demo node, the rest are honest
     fallbacks (a local node on the standard RPC port 16210). A user-typed
     endpoint always wins and is never auto-swapped. */
  const DEFAULT_RPCS = [
    '/api/rpc',
    'http://127.0.0.1:16210/',
  ];
  const DEFAULT_RPC = DEFAULT_RPCS[0];
  const LS_RPC = 'postern_explorer_rpc';       // shared with the explorer page
  const LS_VANTAGES = 'postern_network_vantages';

  const rpcInput = $('#rpc'), connEl = $('#conn'), errEl = $('#err');
  let timer = null, rpcId = 0;
  let failedOver = null; // the primary endpoint we fell back FROM, for an honest note

  let _storedRpc = localStorage.getItem(LS_RPC);
  if (_storedRpc && /blochv-node\.fly\.dev/.test(_storedRpc)) { _storedRpc = null; localStorage.removeItem(LS_RPC); }
  rpcInput.value = (_storedRpc || DEFAULT_RPC).trim();

  const norm = (u) => String(u || '').trim().replace(/\/+$/, '');
  const endpoint = () => norm(rpcInput.value);
  const DEFAULT_SET = DEFAULT_RPCS.map(norm);
  const isDefaultEndpoint = (ep) => DEFAULT_SET.includes(norm(ep));
  const isHttpUrl = (u) => /^http:\/\//i.test(u || '');

  async function rpcTo(ep, method, params = [], timeoutMs = 8000) {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), timeoutMs);
    try {
      const r = await fetch(norm(ep) + '/', {
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
  const rpc = (method, params, timeoutMs) => rpcTo(endpoint(), method, params, timeoutMs);

  /* First live-contact call, with bundled-default failover (see the list note).
     Only hops between bundled defaults, and only when the user is on one; a
     node the user typed is never swapped — its failure goes to the error UX. */
  async function connectPrimary() {
    const primary = endpoint();
    try {
      return await rpc('getnetworkinfo');
    } catch (e) {
      if (!isDefaultEndpoint(primary)) throw e;
      for (const cand of DEFAULT_SET) {
        if (norm(cand) === norm(primary)) continue;
        try {
          const net = await rpcTo(cand, 'getnetworkinfo', [], 7000);
          rpcInput.value = cand;
          localStorage.setItem(LS_RPC, cand);
          failedOver = primary;
          return net;
        } catch (_) { /* try the next bundled default */ }
      }
      throw e;
    }
  }

  /* ── wake/retry with exponential backoff ──────────────────────────────
     Same rationale as the explorer page: the default demo node is a Fly
     machine that AUTO-STOPS when idle and cold-starts (~2-5 s, sometimes
     more) on the first request, so a first failed RPC usually means
     "waking", not "down". Retry with backoff (1 s → 2 s → 4 s → 8 s → 8 s
     → 8 s between attempts, each attempt bounded by the ~8 s per-request
     timeout — roughly 30-40 s of patience overall) behind an honest
     "waking / reconnecting" state before any hard error. No uptime is
     promised — the demo node stays disposable. */
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
  const val = (v) => (v == null) ? DASH : esc(v);
  function setConn(state, txt) { connEl.className = 'conn' + (state ? ' ' + state : ''); connEl.textContent = txt; }
  const stat = (k, v, sub, hero) => `<div class="stat${hero ? ' hero-num' : ''}"><div class="k">${k}</div><div class="v">${v}</div>${sub ? `<div class="sub">${sub}</div>` : ''}</div>`;

  /* ── primary node tiles ── */
  function renderStats(net, peersRes) {
    const peerCount = net.peers != null ? net.peers
      : (peersRes && peersRes.peer_count != null ? peersRes.peer_count : null);
    const syncBadge = net.syncing
      ? '<span class="badge warn">syncing</span>'
      : '<span class="badge ok">synced</span>';
    $('#stats').innerHTML = [
      stat('Connected peers', commas(peerCount), 'as reported by this one node — single vantage, not the network size', true),
      stat('Height', commas(net.blocks)),
      stat('Blue score', commas(net.blue_score)),
      stat('Sync status', syncBadge),
      stat('Mempool', commas(net.mempool) + ' <small>txs</small>'),
      stat('Node reports network', val(net.network || net.chain),
        '<strong>unaudited mainnet beta · 51%-attackable · no value claim</strong> — whatever the node calls it'),
      stat('Protocol', val(net.net_protocol != null ? net.net_protocol : net.protocol)),
      stat('Node version', val(net.version)),
    ].join('');
    const note = $('#peernote');
    if (peerCount === 0) {
      note.innerHTML = '<strong>This node currently sees 0 peers</strong> — it may be isolated, or the network is small. That zero is reported honestly, not papered over: on a nascent mainnet beta with very few nodes, a node with no inbound connections is a normal sight.';
    } else if (peerCount != null) {
      note.innerHTML = 'This node holds <strong>' + commas(peerCount) + '</strong> peer connection' + (peerCount === 1 ? '' : 's') + ' right now. That is its own view only — it says nothing about how many nodes exist in total (no one can know that for an ownerless protocol).';
    } else {
      note.textContent = 'This node did not report a peer count.';
    }
  }

  function renderPeers(peersRes) {
    const list = (peersRes && Array.isArray(peersRes.peers)) ? peersRes.peers : [];
    const box = $('#peers');
    if (!list.length) {
      box.innerHTML = '<div class="peer"><span class="paddr">no peer connections reported — this node currently sees 0 peers (it may be isolated, or the network is small)</span></div>';
      return;
    }
    box.innerHTML = list.map((p) => {
      if (typeof p === 'string') return `<div class="peer"><span class="pid">${esc(p)}</span></div>`;
      return `<div class="peer"><div class="pid">${val(p.peer_id || p.id)}</div><div class="paddr">${val(p.ip || p.address || p.addr)}</div></div>`;
    }).join('');
  }

  function renderSkeleton() {
    $('#stats').innerHTML = Array.from({ length: 8 }, () => stat('…', DASH)).join('');
    $('#peers').innerHTML = '<div class="peer"><span class="paddr">waiting for a node connection…</span></div>';
    $('#peernote').textContent = '';
  }

  /* ── honest failure UX (down vs CORS vs mixed content are indistinguishable) ── */
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
    const mixed = location.protocol === 'https:' && isHttpUrl(endpoint());
    errEl.className = 'errpanel';
    errEl.style.display = 'block';
    if (networkLike) {
      errEl.innerHTML = `<h3>Could not reach the node</h3>
        <p>The request to <code>${esc(endpoint() || '(empty)')}</code> ${aborted ? 'timed out' : 'failed before a reply arrived'}, and automatic retries with backoff (~30-40 s, enough to cover the demo node's cold start from sleep) failed too. From a browser these causes look identical, so all are listed honestly rather than guessing:</p>
        <ul>
          <li><span class="cause">Node down or unreachable.</span> Confirm the node is running and its JSON-RPC is listening at that address.</li>
          <li><span class="cause">CORS blocked.</span> If the node does not send <code>Access-Control-Allow-Origin</code>, the browser blocks this page from reading the reply even when the node is up and answering. Fixes: put the node behind a CORS-enabled reverse proxy, enable its CORS flag, or use the desktop (Tauri) build, which is not subject to browser CORS.</li>
          ${mixed ? '<li><span class="cause">Mixed content.</span> This page is served over HTTPS but the endpoint is <code>http://</code> — browsers block that. Use an HTTPS endpoint, or open this page over file:// or plain HTTP.</li>' : ''}
          <li><span class="cause">CSP.</span> This page's Content-Security-Policy allows HTTPS endpoints plus <code>http://127.0.0.1</code> / <code>localhost</code>; other plain-http hosts are blocked by design.</li>
        </ul>
        ${retryButton()}
        <p class="raw">raw error: ${esc(msg)}</p>`;
      wireRetryButton();
    } else {
      errEl.innerHTML = `<h3>The node replied with an error</h3>
        <p>The endpoint is reachable but returned: <strong>${esc(msg)}</strong></p>
        ${retryButton()}`;
      wireRetryButton();
    }
  }

  /* ── vantage points (user-supplied, non-authoritative) ── */
  function loadVantages() {
    try {
      const v = JSON.parse(localStorage.getItem(LS_VANTAGES) || '[]');
      return Array.isArray(v) ? v.filter((x) => typeof x === 'string') : [];
    } catch (e) { return []; }
  }
  const saveVantages = (v) => localStorage.setItem(LS_VANTAGES, JSON.stringify(v));
  let vantages = loadVantages();
  const vantageState = new Map(); // ep -> {status, peers, height, network, updated, detail}

  function renderVantages() {
    const tb = $('#vantages tbody');
    if (!vantages.length) {
      tb.innerHTML = `<tr><td colspan="7"><div class="empty">No extra vantage points yet. Add a node endpoint above to compare what different nodes see. (The primary node above is your first vantage point.)</div></td></tr>`;
      return;
    }
    tb.innerHTML = vantages.map((ep, i) => {
      const s = vantageState.get(ep) || {};
      let badge;
      if (s.status === 'ok') badge = '<span class="badge ok">reachable</span>';
      else if (s.status === 'err') badge = `<span class="badge err" title="${esc(s.detail || '')}">unreachable / CORS-blocked</span>`;
      else badge = '<span class="badge">querying…</span>';
      return `<tr>
        <td class="mono">${esc(ep)}</td>
        <td>${badge}</td>
        <td class="mono">${s.status === 'ok' ? commas(s.peers) : DASH}</td>
        <td class="mono">${s.status === 'ok' ? commas(s.height) : DASH}</td>
        <td class="mono">${s.status === 'ok' ? val(s.network) : DASH}</td>
        <td class="mono">${val(s.updated)}</td>
        <td><button class="btn small" data-rm="${i}" type="button" aria-label="remove ${esc(ep)}">remove</button></td>
      </tr>`;
    }).join('');
    tb.querySelectorAll('button[data-rm]').forEach((b) => {
      b.onclick = () => {
        vantages.splice(+b.dataset.rm, 1);
        saveVantages(vantages);
        renderVantages();
      };
    });
  }

  async function refreshVantage(ep) {
    try {
      const net = await rpcTo(ep, 'getnetworkinfo', [], 7000);
      vantageState.set(ep, {
        status: 'ok',
        peers: net.peers,
        height: net.blocks,
        network: net.network || net.chain,
        updated: new Date().toLocaleTimeString(),
      });
    } catch (e) {
      vantageState.set(ep, {
        status: 'err',
        detail: (e && e.message) || String(e),
        updated: new Date().toLocaleTimeString(),
      });
    }
  }

  async function refreshVantages() {
    if (!vantages.length) { renderVantages(); return; }
    renderVantages();
    await Promise.all(vantages.map(refreshVantage));
    renderVantages();
  }

  $('#vadd').onclick = () => {
    const raw = norm($('#vaddr').value);
    const msg = $('#vmsg');
    if (!raw) return;
    if (!/^https?:\/\/[^\s]+$/i.test(raw)) {
      msg.textContent = 'Enter a full http(s):// endpoint URL.';
      return;
    }
    if (isHttpUrl(raw) && !/^http:\/\/(127\.0\.0\.1|localhost)([:/]|$)/i.test(raw)) {
      msg.textContent = 'Note: this page’s CSP (and, on HTTPS, mixed-content rules) block plain-http hosts other than 127.0.0.1/localhost — that endpoint will show as unreachable. Use HTTPS for remote nodes.';
    } else {
      msg.textContent = '';
    }
    if (vantages.includes(raw) || raw === endpoint()) {
      msg.textContent = 'That endpoint is already being watched.';
      return;
    }
    vantages.push(raw);
    saveVantages(vantages);
    $('#vaddr').value = '';
    refreshVantages();
  };
  $('#vaddr').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#vadd').click(); });

  /* ── main refresh ──
     Doubles as the heartbeat: the auto-refresh interval re-runs this, and a
     mid-session failure goes back through the wake/backoff loop (an honest
     "reconnecting…" state) instead of jumping straight to a hard error.
     While reconnecting the last-seen data stays on screen; only a hard
     failure (whole backoff schedule exhausted) blanks it to the skeleton. */
  async function refresh() {
    if (refreshing) return; // a wake/backoff cycle is already running
    refreshing = true;
    try {
      refreshVantages(); // independent of the primary node's health
      if (!endpoint()) {
        setConn('err', 'no node set');
        renderSkeleton();
        errEl.className = 'errpanel';
        errEl.style.display = 'block';
        errEl.innerHTML = `<h3>No node configured</h3><p>Enter a node's JSON-RPC endpoint above and press <strong>Connect</strong>.</p>`;
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
      const peersRes = await rpc('getpeers').catch(() => null);
      try { renderStats(net, peersRes); } catch (e) { console.error('renderStats', e); }
      try { renderPeers(peersRes); } catch (e) { console.error('renderPeers', e); }
      $('#updated').textContent = 'last updated ' + new Date().toLocaleTimeString()
        + (failedOver ? ' · primary node ' + failedOver + ' unreachable — showing ' + endpoint() : '')
        + ' · auto-refresh every ' + Math.max(5, parseInt($('#interval').value, 10) || 12) + 's while this tab is visible';
    } finally {
      refreshing = false;
      if (queuedRefresh) { queuedRefresh = false; refresh(); }
    }
  }

  /* ── scheduling ── */
  function schedule() {
    if (timer) clearInterval(timer);
    if ($('#auto').checked) {
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
  renderVantages();
  refresh();
  schedule();
})();
