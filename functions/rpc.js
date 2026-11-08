// Cloudflare Pages Function — same-origin HTTPS proxy to the CANONICAL Bloch-SIS
// node's JSON-RPC 2.0 endpoint, mounted at route `/rpc`.
//
// WHY THIS EXISTS
// ---------------
// The Postern wallets (mobile PWA + desktop) must read balances/height and
// broadcast transactions against the *canonical* chain over HTTPS. The canonical
// node speaks plain-HTTP JSON-RPC, so a browser can't call it directly (mixed
// content). This Function runs on Cloudflare's edge, fetches the node
// server-side, and returns the result same-origin over HTTPS.
//
// It replaces the old public relay (blochv-node.fly.dev) which had fallen onto a
// lighter, OFF-CANONICAL fork (~399,001). The upstream here is node3, the
// canonical miner that stays at the chain tip.
//
// TRUST / HONESTY
// ---------------
// - Reads are public and forwarded verbatim.
// - The ONLY write forwarded is `sendrawtransaction` — already-locally-signed
//   transaction bytes. Keys / mnemonics / passwords NEVER pass through here.
// - The upstream node requires an X-API-Key for non-local writes; that key is a
//   Pages SECRET (env.UPSTREAM_RPC_KEY) attached ONLY to `sendrawtransaction`,
//   NEVER logged, NEVER returned, NEVER sent on a read.
// - This proxies to a canonical-but-mainnet-beta node: unaudited, low-hashrate,
//   51%-attackable — the wallet UI keeps its zero-value / reference-prototype
//   disclaimers. This proxy adds reachability, not security.
//
// UPSTREAM ADDRESSING NOTE
// ------------------------
// Cloudflare Workers `fetch()` rejects a bare IP (CF error 1003) and only allows
// standard ports (80/443/8080/8443/…), NOT the node's 16210. So the default
// upstream is a HOSTNAME via nip.io wildcard DNS → the node's IP, on port 8080
// which the box forwards to the node's RPC (16210). Override with env.UPSTREAM_RPC
// (must itself be a Workers-fetchable host+port). The canonical node is
// 45.32.154.137; direct `http://45.32.154.137:16210` is NOT edge-reachable.
const DEFAULT_UPSTREAM = 'http://45.76.138.60.nip.io:8080/';

// Method allowlist. Reads are drawn from the node's RPC surface
// (docs/openapi.yaml). The ONLY write is `sendrawtransaction`. Mining writes
// (submitblock / getblocktemplate) are deliberately NOT exposed.
const READ_METHODS = new Set([
  // chain state
  'getnetworkinfo', 'getblockcount', 'getdaginfo', 'getmempoolinfo',
  'getpeerinfo', 'getpeers', 'getchainstats', 'gethashrate',
  'getsupplydistribution', 'getdifficultyhistory', 'getblocktimepercentiles',
  'getpools', 'getattestation', 'gettipinfo',
  // blocks
  'getblockhash', 'getblock', 'getblockbyheight', 'getrecentblocks',
  // transactions
  'gettransaction', 'gettxstatus', 'decoderawtransaction',
  // addresses / wallet reads
  'getbalance', 'getaddressbalance', 'getaddressbalance_at_height',
  'getaddressinfo', 'getaddresscount', 'getutxos', 'listtransactions',
]);
const WRITE_METHODS = new Set([
  'sendrawtransaction',
]);

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'POST, OPTIONS',
  'access-control-allow-headers': 'content-type',
  'access-control-max-age': '86400',
};

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      ...CORS,
    },
  });
}

// A JSON-RPC error, always with HTTP 200 so the client parses the body.
function rpcError(code, message, id) {
  return json({ jsonrpc: '2.0', error: { code, message }, id: id ?? null });
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: CORS });
}

export async function onRequestPost({ request, env }) {
  const upstream = (env && env.UPSTREAM_RPC) || DEFAULT_UPSTREAM;

  let payload;
  try {
    payload = JSON.parse(await request.text());
  } catch (_) {
    return rpcError(-32700, 'parse error', null);
  }

  const id = payload && payload.id;
  const method = payload && payload.method;
  if (typeof method !== 'string') {
    return rpcError(-32600, 'invalid request: missing method', id);
  }

  const isRead = READ_METHODS.has(method);
  const isWrite = WRITE_METHODS.has(method);
  if (!isRead && !isWrite) {
    return rpcError(-32601, `method '${method}' is not allowed via this proxy`, id);
  }

  // Re-serialize from the parsed, allowlisted payload — never forward arbitrary
  // extra body content. Only writes get the upstream API key.
  const headers = { 'content-type': 'application/json' };
  if (isWrite && env && env.UPSTREAM_RPC_KEY) {
    headers['X-API-Key'] = env.UPSTREAM_RPC_KEY;
  }
  const body = JSON.stringify({
    jsonrpc: '2.0',
    id: id ?? null,
    method,
    params: (payload && payload.params) || [],
  });

  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 8000);
  let resp;
  try {
    resp = await fetch(upstream, { method: 'POST', headers, body, signal: ctl.signal });
  } catch (_) {
    clearTimeout(timer);
    // Never leak a 500/stack — pass a clean JSON-RPC error through.
    return rpcError(-32000, 'upstream node unreachable', id);
  }
  clearTimeout(timer);

  const text = await resp.text();
  if (!resp.ok) {
    // Don't relay a possibly-HTML upstream error page; normalize to JSON-RPC.
    return rpcError(-32000, `upstream node error (HTTP ${resp.status})`, id);
  }
  // Return the upstream JSON verbatim, same-origin, with CORS + no-store.
  return new Response(text, {
    status: 200,
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      ...CORS,
    },
  });
}

// Any other method → 405 (only POST/OPTIONS are valid).
export async function onRequest({ request }) {
  if (request.method === 'POST' || request.method === 'OPTIONS') return; // handled above
  return new Response('Method Not Allowed', {
    status: 405,
    headers: { allow: 'POST, OPTIONS', ...CORS },
  });
}
