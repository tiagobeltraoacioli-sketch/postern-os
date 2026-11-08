// Cloudflare Pages Function — same-origin HTTPS proxy to a Bloch-SIS node's
// JSON-RPC. The public explorer is served over HTTPS; a node's RPC is plain
// HTTP, so a browser can't call it directly (mixed content). This Function runs
// on Cloudflare's edge, fetches the node server-side (no mixed-content rule),
// and returns the result same-origin. It is READ-ONLY: only explorer read verbs
// are forwarded, so the public proxy can never be used to relay a write
// (sendrawtransaction etc.) to the node — those still require the node's
// own X-API-Key, which is never exposed here.
//
// Upstream is an Edgevana node that stays at the chain tip (the canonical
// miner), so the explorer tracks the live chain without depending on a
// weaker relay that falls behind during a flood.

// Upstream node RPC. Port 8080 redirects to the node's RPC (16210) on the box —
// Cloudflare Workers fetch() only allows standard ports (80/443/8080/8443/…),
// not 16210. A HOSTNAME (via nip.io wildcard DNS → the node's IP) is used, not a
// raw IP, because a Workers fetch() to a bare IP is rejected with CF error 1003.
const NODE_RPC = 'http://45.76.138.60.nip.io:8080/';

const READ_METHODS = new Set([
  'getrecentblocks', 'getblockcount', 'getblocktemplate', 'getblock',
  'getblockbyheight', 'getdaginfo', 'getnetworkinfo', 'getpeers',
  'getaddressinfo', 'gettipinfo', 'getmempoolinfo', 'getblockhash',
]);

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });
}

export async function onRequestPost({ request }) {
  const body = await request.text();
  let payload;
  try { payload = JSON.parse(body); } catch (_) {
    return json({ jsonrpc: '2.0', error: { code: -32700, message: 'parse error' }, id: null }, 400);
  }
  const method = payload && payload.method;
  if (!READ_METHODS.has(method)) {
    return json({ jsonrpc: '2.0', error: { code: -32601, message: 'method not allowed via public read proxy' }, id: (payload && payload.id) ?? null }, 403);
  }
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 20000);
    const upstream = await fetch(NODE_RPC, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body,
      signal: ctl.signal,
    });
    clearTimeout(t);
    const text = await upstream.text();
    return new Response(text, {
      status: upstream.status,
      headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
    });
  } catch (_) {
    return json({ jsonrpc: '2.0', error: { code: -32000, message: 'upstream node unreachable' }, id: (payload && payload.id) ?? null }, 502);
  }
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: { allow: 'POST, OPTIONS' } });
}
