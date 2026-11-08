#!/usr/bin/env node
/*
 * Bloch Explorer — static page generator (Postern Labs identity).
 *
 * Emits fully self-contained HTML pages (all CSS + JS inlined, no CDN, no
 * external fonts, no images). The ONLY network requests the emitted pages
 * ever make are JSON-RPC POSTs to the node endpoint(s) the user configures.
 *
 * The base stylesheet is read verbatim from ../site/index.html so the
 * explorer is pixel-identical to the Postern Labs site identity; explorer
 * widget styles are appended using the same custom properties.
 *
 * Run:  node explorer/build.js
 */
"use strict";

const fs = require("fs");
const path = require("path");

const OUT = __dirname;

/* ── identity stylesheet, taken verbatim from the site ─────────────── */
const sitePage = fs.readFileSync(path.join(__dirname, "..", "site", "index.html"), "utf8");
const styleMatch = sitePage.match(/<style>([\s\S]*?)<\/style>/);
if (!styleMatch) throw new Error("could not extract the site stylesheet from site/index.html");
const SITE_CSS = styleMatch[1];

/* ── explorer additions — same variables, same family ──────────────── */
const EXPLORER_CSS = `
/* ---------- explorer widgets (Postern identity additions) ---------- */
.toolhero { padding: 2.8rem 0 2.2rem; }
.toolhero .rule { width: 3.5rem; height: 3px; background: var(--brass); margin-bottom: 1.6rem; border-radius: 2px; }

.cfgbar {
  display: flex; gap: .7rem 1rem; flex-wrap: wrap; align-items: center;
  background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
  padding: .85rem 1rem; margin-top: 1.2rem;
}
.cfgbar .grow { flex: 1 1 18rem; min-width: 14rem; }
.cfgbar label { font-size: .8rem; color: var(--text-dim); display: inline-flex; align-items: center; gap: .45rem; white-space: nowrap; }
input[type="text"], input[type="url"], input[type="number"] {
  background: var(--surface-2); border: 1px solid var(--border-hi); color: var(--text);
  font-family: var(--font-mono); font-size: .86rem; padding: .55rem .7rem; border-radius: 6px;
  width: 100%;
}
input[type="number"] { width: 4.2rem; }
input[type="checkbox"] { accent-color: var(--brass); width: .95rem; height: .95rem; }
input:focus-visible { outline: 2px solid var(--brass); outline-offset: 1px; }
button.btn { cursor: pointer; font-family: var(--font-ui); font-size: .9rem; background: var(--surface); }
button.btn.primary { background: var(--brass); }
button.btn.small { padding: .35rem .7rem; font-size: .8rem; }

.conn {
  display: inline-flex; align-items: center; gap: .45rem;
  font-size: .78rem; font-weight: 700; letter-spacing: .06em; text-transform: uppercase;
  padding: .2rem .7rem; border-radius: 99px; border: 1px solid var(--border-hi);
  color: var(--text-dim); white-space: nowrap;
}
.conn::before { content: ""; width: .5rem; height: .5rem; border-radius: 50%; background: currentColor; }
.conn.ok   { color: var(--ok); border-color: var(--ok); }
.conn.warn { color: var(--brass-hi); border-color: var(--brass-dim); }
.conn.err  { color: var(--danger); border-color: var(--danger); }

.statgrid { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fill, minmax(13rem, 1fr)); margin-top: 1.4rem; }
.stat { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: .95rem 1.05rem; }
.stat .k { font-size: .68rem; letter-spacing: .14em; text-transform: uppercase; color: var(--muted); font-weight: 700; }
.stat .v { font-family: var(--font-mono); font-size: 1.3rem; font-weight: 650; color: var(--text); margin-top: .35rem; overflow-wrap: anywhere; line-height: 1.3; }
.stat .v small { font-size: .74rem; color: var(--muted); font-weight: 500; font-family: var(--font-ui); }
.stat .sub { font-size: .78rem; color: var(--text-dim); margin-top: .3rem; }
.stat.hero-num .v { font-size: 2.5rem; }

.badge.ok   { color: var(--ok); border-color: var(--ok); }
.badge.warn { color: var(--brass-hi); border-color: var(--brass-dim); }
.badge.err  { color: var(--danger); border-color: var(--danger); }

.updated { font-size: .8rem; color: var(--muted); font-family: var(--font-mono); margin-top: .8rem; }

.errpanel {
  background: var(--surface); border: 1px solid var(--danger); border-left: 4px solid var(--danger);
  border-radius: 8px; padding: 1.15rem 1.35rem; margin: 1.2rem 0; max-width: 52rem;
}
.errpanel h3 { color: var(--danger); font-size: .95rem; letter-spacing: .04em; text-transform: uppercase; margin-bottom: .5rem; }
.errpanel p, .errpanel li { color: var(--text-dim); font-size: .92rem; }
.errpanel ul { margin: .55rem 0 0 1.2rem; }
.errpanel li + li { margin-top: .35rem; }
.errpanel .cause { color: var(--text); font-weight: 650; }
.errpanel .raw { margin-top: .7rem; font-size: .78rem; color: var(--muted); font-family: var(--font-mono); overflow-wrap: anywhere; }

.detailpanel {
  background: var(--surface); border: 1px solid var(--border-hi); border-left: 4px solid var(--brass);
  border-radius: 10px; padding: 1.25rem 1.4rem; margin: 1.2rem 0;
}
.detailpanel h3 { display: flex; align-items: center; gap: .6rem; flex-wrap: wrap; margin-bottom: .9rem; }
.detailpanel .close { margin-left: auto; }
.kvlist { display: grid; grid-template-columns: minmax(8rem, 11rem) 1fr; gap: .5rem 1.2rem; font-size: .88rem; align-items: start; }
.kvlist .k { color: var(--muted); }
.kvlist .v { font-family: var(--font-mono); color: var(--text-dim); overflow-wrap: anywhere; }
@media (max-width: 40rem) { .kvlist { grid-template-columns: 1fr; } .kvlist .k { margin-top: .5rem; } }
.txbox {
  background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px;
  padding: .7rem .9rem; margin-top: .6rem; font-size: .84rem; font-family: var(--font-mono); overflow-wrap: anywhere;
}
.txbox .meta { color: var(--muted); font-family: var(--font-ui); margin-top: .25rem; }

.searchrow { display: flex; gap: .7rem; flex-wrap: wrap; margin-top: 1rem; }
.searchrow .grow { flex: 1 1 20rem; min-width: 15rem; }

tbody tr.rowlink { cursor: pointer; }
tbody tr.rowlink:hover td { background: var(--surface-2); }
td.mono, th.mono { font-family: var(--font-mono); }
.empty { color: var(--muted); font-size: .88rem; padding: 1.1rem; text-align: center; }

.peerlist { display: grid; gap: .6rem; grid-template-columns: repeat(auto-fill, minmax(16rem, 1fr)); margin-top: 1rem; }
.peer { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: .6rem .8rem; font-family: var(--font-mono); font-size: .8rem; overflow-wrap: anywhere; }
.peer .pid { color: var(--text); }
.peer .paddr { color: var(--muted); }

.copyable { cursor: copy; }
.copyable.copied { color: var(--ok); }
.hashlink { color: var(--brass-hi); }

/* ---------- hashrate chart ---------- */
.chartwrap { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1rem 1rem .55rem; margin-top: 1.4rem; }
.chartwrap .cap { font-size: .78rem; color: var(--muted); font-family: var(--font-mono); margin-top: .4rem; }
canvas.hashchart { display: block; width: 100%; height: 320px; }
@media (max-width: 40rem) { canvas.hashchart { height: 240px; } input[type="number"].winbox { width: 3.6rem; } }
`;

/* ── shared chrome ──────────────────────────────────────────────────── */
const GLYPH = `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" aria-hidden="true"><path class="gate-arch" d="M5 22V11a7 7 0 0 1 14 0v11"/><path class="gate-line" d="M12 4v18" stroke-width="1.1"/></svg>`;

const NAV = [
  ["/index.html", "Home"],
  ["/postern-vs-bloch.html", "Postern & Bloch"],
  ["/products.html", "Products"],
  ["/downloads.html", "Downloads"],
  ["/run-a-node.html", "Run a node"],
  ["/disclaimer.html", "Disclaimer"],
  ["index.html", "Explorer"],
  ["hashrate.html", "Hashrate"],
  ["network.html", "Network"],
];

function header(active) {
  const links = NAV.map(
    ([href, label]) =>
      `<a href="${href}"${href === active ? ' aria-current="page"' : ""}>${label}</a>`
  ).join("\n      ");
  return `<a class="skip" href="#main">Skip to content</a>
<header class="site-head">
  <div class="inner">
    <a class="wordmark" href="/index.html">${GLYPH}<span>Postern&nbsp;<span class="lab">Labs</span></span></a>
    <nav aria-label="Site">
      ${links}
    </nav>
  </div>
</header>
<div class="beta-ribbon" role="note" aria-label="Mainnet beta status warning">
  <strong>MAINNET BETA.</strong> Unaudited · <strong>difficulty-driven k-ramp</strong> (k=4 now, rising with hashrate — a structural filter, not a security claim) ·
  very few nodes, low hashrate — 51%-attackable · the coin carries <strong>no value claim</strong> and is not a security.
  <a href="/disclaimer.html">Full disclaimer&nbsp;→</a>
</div>
<div class="beta-ribbon" role="note" aria-label="Node update notice">
  <strong>🛰 Running a node?</strong> Node <strong>v0.1.0-alpha2</strong> retires the fixed k=8 gate for a <strong>difficulty-driven k-ramp</strong> — genesis sync works again, and the <strong>signed snapshot</strong> is an optional one-command fast-sync. <a href="/snapshot.html">Snapshot fast-sync — how&nbsp;→</a>
</div>`;
}

const FOOTER = `<footer class="site-foot">
  <div class="wrap">
    <div class="cols">
      <div>
        <h4>Bloch Explorer — a Postern Labs tool</h4>
        <p>Reads the ownerless <strong>Bloch-SIS-PoW</strong> protocol through a node's public JSON-RPC: <code>getnetworkinfo</code>, <code>getblockcount</code>, <code>getdaginfo</code>, <code>getrecentblocks</code>, <code>getblock</code>, <code>getblockbyheight</code>, <code>getaddressinfo</code>, <code>getpeers</code>. Nothing privileged — anyone can build the same.</p>
        <p>No tracking. No analytics. The only network requests these pages make are the JSON-RPC calls to the node endpoint(s) you configure.</p>
      </div>
      <div>
        <h4>Site</h4>
        <nav aria-label="Footer">
          <a href="/index.html">Home</a>
          <a href="/postern-vs-bloch.html">Postern &amp; Bloch-SIS-PoW</a>
          <a href="/products.html">Products</a>
          <a href="/downloads.html">Downloads</a>
          <a href="/run-a-node.html">Run a node</a>
          <a href="/disclaimer.html">Disclaimer &amp; legal</a>
          <a href="index.html">Explorer</a>
          <a href="network.html">Network</a>
        </nav>
      </div>
      <div>
        <h4>Standing disclosures</h4>
        <p>This chain is a <strong>mainnet beta</strong> — a designation, not a security claim: <strong>unaudited</strong> (audit contracted, not done), with <strong>very few nodes and low hashrate — 51%-attackable</strong>. The Module-SIS gate is a <strong>difficulty-driven k-ramp</strong> (node v0.1.0-alpha2): k=4 today, rising toward k=8 as the network's own difficulty grows and easing back if hashrate falls. It is <strong>not a security claim by itself</strong> (real security is cumulative SHAKE-256 hashcash work — raising k adds no cryptographic hardness at β=q/16). A brand-new node can <strong>sync from genesis</strong> or fast-sync from the optional <strong>signed snapshot</strong>. Whatever network string a node reports, treat confirmations as reversible.</p>
        <p>The coin is <strong>not a security and not an asset</strong> — it carries no value claim. No token sale, no listing effort, no market-making, no price. A 17% founder premine is disclosed in full. Do not attach value.</p>
      </div>
    </div>
    <p class="legal">The Bloch-SIS-PoW protocol is ownerless and is not a Postern Labs product; there is no official node, site, or explorer. This explorer is one independent tool on that commons, by Postern Labs. It lives at <code>gitlab.com/blochsispow-group/BlochSISPoW-project</code> (shown as text on purpose — there is no official site to link to).</p>
  </div>
</footer>`;

/*
 * CSP note — connect-src.
 * These pages let the user point at ANY node endpoint (the protocol is
 * ownerless; pinning one host would quietly crown it "the" node). That is a
 * deliberate tradeoff: `connect-src https:` allows the page to talk to any
 * HTTPS host, which is broader than pinning `https://blochv-node.fly.dev`.
 * Mitigations: every script is inline and reviewed here, no external code can
 * ever load (script-src has no hosts), and all node-supplied strings are
 * HTML-escaped before rendering. http://127.0.0.1 / localhost are included so
 * the explorer works against a local dev node when the page itself is opened
 * over file:// or plain HTTP (from an HTTPS origin, browsers additionally
 * block plain-http requests as mixed content — the pages explain that
 * honestly instead of failing silently).
 */
const CSP =
  "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; " +
  "img-src 'self' data:; connect-src https: http://127.0.0.1:* http://localhost:*; " +
  "base-uri 'none'; form-action 'none'";

const CSP_STATIC =
  "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; " +
  "connect-src 'none'; base-uri 'none'; form-action 'none'";

function page({ file, title, desc, active, body, script, staticCsp, extraHead }) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<!-- connect-src is https: + localhost (not pinned to one node) so users can point
     the explorer at any node they run or trust; scripts stay inline-only, so no
     external code can load. See explorer/build.js for the full tradeoff note. -->
<meta http-equiv="Content-Security-Policy" content="${staticCsp ? CSP_STATIC : CSP}">
<meta name="description" content="${desc}">
<meta name="color-scheme" content="dark light">
${extraHead || ""}<title>${title}</title>
<style>${SITE_CSS}${staticCsp ? "" : EXPLORER_CSS}</style>
</head>
<body>
${header(active)}
<main id="main">
${body}
</main>
${FOOTER}
${script ? `<script>\n${script}\n</script>` : ""}</body>
</html>
`;
}

/* ── page bodies ────────────────────────────────────────────────────── */

const EXPLORER_BODY = `
<section class="toolhero">
  <div class="wrap">
    <div class="rule" aria-hidden="true"></div>
    <p class="kicker">Postern Labs · tools · mainnet beta</p>
    <h1>Bloch Explorer</h1>
    <p class="lede">Blocks, transactions and addresses on the <strong>Bloch-SIS-PoW</strong> mainnet beta, read live from a node's JSON-RPC. The protocol is <strong>ownerless</strong> — this is one independent tool on it, by Postern Labs, not "the official explorer" (there is none). <strong>Mainnet beta — unaudited, low-hashrate, 51%-attackable · the coin carries no value claim.</strong></p>
    <div class="cfgbar">
      <div class="grow">
        <label for="rpc" style="display:block;margin-bottom:.3rem">Node RPC endpoint (JSON-RPC 2.0, POST)</label>
        <input type="url" id="rpc" spellcheck="false" placeholder="https://your-node.example  or  http://127.0.0.1:8645">
      </div>
      <button class="btn primary" id="connect" type="button">Connect</button>
      <label><input type="checkbox" id="auto" checked> auto-refresh</label>
      <label>every <input type="number" id="interval" value="12" min="5" max="600" aria-label="refresh interval in seconds"> s</label>
      <span class="conn" id="conn" role="status" aria-live="polite">idle</span>
    </div>
    <p class="small dim" style="margin-top:.6rem">Point this at any Bloch node you run or trust. The pre-filled default is Postern's <strong>disposable demo node</strong> — a convenience, not official infrastructure. Requests go only to the endpoint you set.</p>
  </div>
</section>

<section aria-labelledby="ov-h">
  <div class="wrap">
    <p class="kicker" id="ov-h">Network overview</p>
    <h2>What the configured node reports.</h2>
    <p class="prose small">Self-reported by one node's RPC — a single vantage point, not a global view. The <a href="network.html">network page</a> says more about that limit. Whatever network string the node reports (<code>getnetworkinfo.network</code> — the live demo node currently reports <code>mainnet</code>; other builds may report a different string), this chain is an <strong>unaudited, 51%-attackable mainnet beta whose coin carries no value claim</strong>.</p>
    <div class="errpanel" id="err" style="display:none" role="alert"></div>
    <div class="statgrid" id="stats" aria-live="polite"></div>
    <p class="updated" id="updated"></p>
  </div>
</section>

<section aria-labelledby="blk-h">
  <div class="wrap">
    <p class="kicker" id="blk-h">Block lookup</p>
    <h2>Open a block by height or hash.</h2>
    <div class="searchrow">
      <div class="grow"><input type="text" id="q" spellcheck="false" placeholder="block height (e.g. 1234) or 64-hex block hash" aria-label="block height or hash"></div>
      <button class="btn" id="go" type="button">Open block</button>
    </div>
    <div id="detail"></div>
  </div>
</section>

<section aria-labelledby="addr-h">
  <div class="wrap">
    <p class="kicker" id="addr-h">Address lookup</p>
    <h2>Balance and UTXOs for a bloch1… address.</h2>
    <p class="prose small">Balances are units on the unaudited mainnet beta. They carry <strong>no value claim</strong> — no price, no market, not a security, not for investment.</p>
    <div class="searchrow">
      <div class="grow"><input type="text" id="qaddr" spellcheck="false" placeholder="bloch1q… / bloch1t… address" aria-label="bloch address"></div>
      <button class="btn" id="goaddr" type="button">Check balance</button>
    </div>
    <div id="addrinfo" aria-live="polite"></div>
  </div>
</section>

<section aria-labelledby="rec-h">
  <div class="wrap">
    <p class="kicker" id="rec-h">Recent blocks</p>
    <h2>The latest blocks the node knows about.</h2>
    <p class="prose small">Click a row for full detail. The list RPC returns height, hash, time, tx count, size and bits; nonce and the SIS witness are only in the per-block view where the node exposes them.</p>
    <div class="tablewrap"><table id="blocks">
      <thead><tr><th>Height</th><th>Hash</th><th>Age</th><th>Txs</th><th>Size</th><th>Bits</th></tr></thead>
      <tbody></tbody>
    </table></div>
  </div>
</section>

<noscript><div class="wrap"><div class="warnpanel" role="note"><h3>JavaScript required</h3><p>This explorer queries a node's JSON-RPC from your browser; with JavaScript disabled it cannot fetch anything. It still makes zero requests to anyone but the node you configure.</p></div></div></noscript>
`;

const NETWORK_BODY = `
<section class="toolhero">
  <div class="wrap">
    <div class="rule" aria-hidden="true"></div>
    <p class="kicker">Postern Labs · tools · mainnet beta</p>
    <h1>Network</h1>
    <p class="lede">How many peers the node you query is connected to, and what it says about itself — refreshed live. <strong>Mainnet beta — unaudited · very few nodes, low hashrate, 51%-attackable · the coin carries no value claim.</strong></p>
    <div class="warnpanel" role="note">
      <h3>What this page can — and cannot — tell you</h3>
      <ul>
        <li><strong>Peer counts are single-vantage.</strong> Each number below is what one node reports about <em>its own</em> peer connections — not a global crawl, census, or "network size". Other nodes may see more, fewer, or different peers.</li>
        <li><strong>There is no authoritative node registry.</strong> The protocol is ownerless; nobody can enumerate "all nodes". The vantage points you add below are user-supplied, not an official list.</li>
        <li><strong>Numbers are self-reported</strong> by each node's RPC and are not independently verified by this page. A node can claim any network string; whatever it claims, treat this chain as a nascent, unaudited, 51%-attackable mainnet beta whose coin carries no value claim.</li>
      </ul>
    </div>
    <div class="cfgbar">
      <div class="grow">
        <label for="rpc" style="display:block;margin-bottom:.3rem">Primary node RPC endpoint (JSON-RPC 2.0, POST)</label>
        <input type="url" id="rpc" spellcheck="false" placeholder="https://your-node.example  or  http://127.0.0.1:8645">
      </div>
      <button class="btn primary" id="connect" type="button">Connect</button>
      <label><input type="checkbox" id="auto" checked> auto-refresh</label>
      <label>every <input type="number" id="interval" value="12" min="5" max="600" aria-label="refresh interval in seconds"> s</label>
      <span class="conn" id="conn" role="status" aria-live="polite">idle</span>
    </div>
    <p class="small dim" style="margin-top:.6rem">Default is Postern's <strong>disposable demo node</strong> — a convenience, not official infrastructure.</p>
  </div>
</section>

<section aria-labelledby="live-h">
  <div class="wrap">
    <p class="kicker" id="live-h">Live status</p>
    <h2>What the primary node reports right now.</h2>
    <div class="errpanel" id="err" style="display:none" role="alert"></div>
    <div class="statgrid" id="stats" aria-live="polite"></div>
    <p class="prose small" id="peernote" style="margin-top:1rem"></p>
    <p class="updated" id="updated"></p>
  </div>
</section>

<section aria-labelledby="peers-h">
  <div class="wrap">
    <p class="kicker" id="peers-h">Peer connections</p>
    <h2>The peers this node is holding open.</h2>
    <p class="prose small">From <code>getpeers</code> on the primary node — again, its own connections only.</p>
    <div class="peerlist" id="peers"></div>
  </div>
</section>

<section aria-labelledby="van-h">
  <div class="wrap">
    <p class="kicker" id="van-h">Known nodes — user-supplied vantage points</p>
    <h2>Compare what different nodes see.</h2>
    <p class="prose small">Add the RPC endpoints of other nodes you run or trust; each is polled with <code>getnetworkinfo</code> and shown side by side. This list lives only in your browser (localStorage) and is <strong>not an authoritative registry</strong> — an ownerless protocol has none. Endpoints must be reachable from your browser: HTTPS (or localhost) and CORS-enabled, otherwise the browser blocks the request and the row will say so.</p>
    <div class="searchrow">
      <div class="grow"><input type="url" id="vaddr" spellcheck="false" placeholder="https://another-node.example" aria-label="vantage point RPC endpoint"></div>
      <button class="btn" id="vadd" type="button">Add vantage point</button>
    </div>
    <p class="small dim" id="vmsg" style="margin-top:.4rem"></p>
    <div class="tablewrap" style="margin-top:1rem"><table id="vantages">
      <thead><tr><th>Endpoint</th><th>Status</th><th>Peers</th><th>Height</th><th>Reported network</th><th>Updated</th><th></th></tr></thead>
      <tbody></tbody>
    </table></div>
  </div>
</section>

<noscript><div class="wrap"><div class="warnpanel" role="note"><h3>JavaScript required</h3><p>This page polls a node's JSON-RPC from your browser; with JavaScript disabled it cannot fetch anything. It still makes zero requests to anyone but the node(s) you configure.</p></div></div></noscript>
`;

function stubBody(oldName) {
  return `
<section class="toolhero">
  <div class="wrap narrow">
    <div class="rule" aria-hidden="true"></div>
    <p class="kicker">Postern Labs · tools · mainnet beta</p>
    <h1>This page moved.</h1>
    <p class="lede">The old <code>${oldName}</code> page was reworked into the Postern Labs identity. Everything it did — network overview, block lookup, address lookup, recent blocks — now lives in the <a href="index.html">Bloch Explorer</a>, and peer/connectivity tracking has its own <a href="network.html">Network page</a>.</p>
    <p class="prose small">You are being redirected automatically. Reminder: this chain is an <strong>unaudited mainnet beta</strong> — very few nodes, low hashrate, 51%-attackable; the Module-SIS gate is a difficulty-driven k-ramp (k=4 today, rising with hashrate — not a security claim by itself); the coin carries no value claim and is not a security.</p>
    <div class="cta-row">
      <a class="btn primary" href="index.html">Open the explorer</a>
      <a class="btn" href="network.html">Network page</a>
    </div>
  </div>
</section>
`;
}

const HASHRATE_BODY = `
<section class="toolhero">
  <div class="wrap">
    <div class="rule" aria-hidden="true"></div>
    <p class="kicker">Postern Labs · tools · mainnet beta</p>
    <h1>Network hashrate</h1>
    <p class="lede">An <strong>estimate</strong> of the <strong>Bloch-SIS-PoW</strong> network hashrate, read live from one node's JSON-RPC — modelled from the difficulty target, the <strong>SIS gate at its current ramp width (k=4 today)</strong>, and block intervals, not measured. The protocol is <strong>ownerless</strong>; this is one independent tool, not "the official explorer" (there is none). <strong>Mainnet beta — unaudited, very low hashrate, 51%-attackable · the coin carries no value claim.</strong></p>
    <div class="cfgbar">
      <div class="grow">
        <label for="rpc" style="display:block;margin-bottom:.3rem">Node RPC endpoint (JSON-RPC 2.0, POST)</label>
        <input type="url" id="rpc" spellcheck="false" placeholder="https://your-node.example  or  http://127.0.0.1:16210">
      </div>
      <label>window <input type="number" class="winbox" id="window" value="80" min="10" max="500" aria-label="number of recent blocks to sample"> blocks</label>
      <button class="btn primary" id="connect" type="button">Connect</button>
      <label><input type="checkbox" id="auto" checked> auto-refresh</label>
      <label>every <input type="number" id="interval" value="15" min="5" max="600" aria-label="refresh interval in seconds"> s</label>
      <span class="conn" id="conn" role="status" aria-live="polite">idle</span>
    </div>
    <p class="small dim" style="margin-top:.6rem">Point this at any Bloch node you run or trust. Requests go only to the endpoint you set. The pre-filled default is Postern's <strong>disposable demo node</strong> — a convenience, not official infrastructure.</p>
  </div>
</section>

<section aria-labelledby="hr-h">
  <div class="wrap">
    <p class="kicker" id="hr-h">Estimate</p>
    <h2>What the difficulty and block times imply.</h2>
    <div class="errpanel" id="err" style="display:none" role="alert"></div>
    <div class="statgrid" id="stats" aria-live="polite"></div>
    <div class="chartwrap">
      <canvas class="hashchart" id="chart" role="img" aria-label="Estimated network hashrate over recent blocks"></canvas>
      <p class="cap">Smoothed hashrate (brass line) over the sampled window; faint dots are per-block instantaneous estimates. The y-axis auto-scales.</p>
    </div>
    <p class="updated" id="updated"></p>
  </div>
</section>

<section aria-labelledby="how-h">
  <div class="wrap">
    <p class="kicker" id="how-h">How this is computed — and why it is only an estimate</p>
    <div class="warnpanel" role="note">
      <ul>
        <li><strong>A model, not a measurement.</strong> To mine a block a candidate must clear <em>both</em> gates, so expected evaluations per block &asymp; <code>[2^256 / (target + 1)] &times; 8^k</code> — the hashcash term (target decoded from <code>bits</code>) times the SIS-gate term. Hashrate &asymp; &Sigma; evaluations &divide; elapsed time over the window. Real hashrate is unobservable; this infers it from difficulty, the gate width, and timing.</li>
        <li><strong>Why the SIS gate is folded in.</strong> Bloch's hashcash target is deliberately <em>loose</em> — most of the work is the lattice gate, so a hashcash-only estimate would read near-zero and mislead. Each of the <code>k</code> residual coefficients must land under <code>β = q/16</code> (~1 in 8), so a valid candidate is ~<code>8^k</code> rarer (k is now a difficulty-driven ramp: k=4 today &rarr; ~4096&times;, up to k=8 &rarr; ~16.7&nbsp;million&times;; the page reads the live width when the node exposes it). This assumes uniform residuals — a modelling assumption, not a proof.</li>
        <li><strong>Single vantage point.</strong> The blocks come from the one node you query, not a global view. A different node may report different recent blocks.</li>
        <li><strong>Noisy at low hashrate.</strong> With few miners and long gaps, per-block numbers swing wildly — hence the smoothing. Treat the trend, not any single point, as meaningful.</li>
        <li><strong>Unaudited mainnet beta</strong>, 51%-attackable at this hashrate; the coin carries no value claim and is not a security.</li>
      </ul>
    </div>
  </div>
</section>

<noscript><div class="wrap"><div class="warnpanel" role="note"><h3>JavaScript required</h3><p>This page estimates hashrate from a node's JSON-RPC in your browser; with JavaScript disabled it cannot fetch anything. It still makes zero requests to anyone but the node you configure.</p></div></div></noscript>
`;

/* ── emit ───────────────────────────────────────────────────────────── */
const explorerJs = fs.readFileSync(path.join(OUT, "explorer.app.js"), "utf8");
const networkJs = fs.readFileSync(path.join(OUT, "network.app.js"), "utf8");
const hashrateJs = fs.readFileSync(path.join(OUT, "hashrate.app.js"), "utf8");
for (const [name, src] of [["explorer.app.js", explorerJs], ["network.app.js", networkJs], ["hashrate.app.js", hashrateJs]]) {
  if (/<\/script/i.test(src)) throw new Error(name + " contains '</script' — would break inlining");
}

const pages = [
  {
    file: "index.html",
    title: "Bloch Explorer — Postern Labs (mainnet beta, unaudited)",
    desc: "Blocks, transactions and addresses on the Bloch-SIS-PoW mainnet beta, read live from a node's JSON-RPC. Unaudited, low-hashrate, 51%-attackable mainnet beta; the coin carries no value claim.",
    active: "index.html",
    body: EXPLORER_BODY,
    script: explorerJs,
  },
  {
    file: "network.html",
    title: "Bloch Network — connected peers · Postern Labs (mainnet beta, unaudited)",
    desc: "Peer connectivity of the Bloch-SIS-PoW mainnet beta as reported by the node you configure — an honest single-vantage view, not a global crawl. Unaudited, 51%-attackable mainnet beta; no value claim on the coin.",
    active: "network.html",
    body: NETWORK_BODY,
    script: networkJs,
  },
  {
    file: "hashrate.html",
    title: "Bloch Hashrate — network hashrate estimate · Postern Labs (mainnet beta, unaudited)",
    desc: "An estimate of the Bloch-SIS-PoW network hashrate from the difficulty target and block intervals reported by the node you configure — a single-vantage estimate, not a measurement. Unaudited, low-hashrate, 51%-attackable mainnet beta; no value claim on the coin.",
    active: "hashrate.html",
    body: HASHRATE_BODY,
    script: hashrateJs,
  },
  {
    file: "bloch-pow-explorer.html",
    title: "Bloch Explorer (moved) — Postern Labs",
    desc: "This page moved: the Bloch explorer now lives at index.html, with a dedicated network page. Unaudited, 51%-attackable mainnet beta; no value claim on the coin.",
    active: "index.html",
    body: stubBody("bloch-pow-explorer.html"),
    staticCsp: true,
    extraHead: `<meta http-equiv="refresh" content="2; url=index.html">\n`,
  },
  {
    file: "blochscan.html",
    title: "Blochscan (moved) — Postern Labs",
    desc: "This page moved: the Bloch explorer now lives at index.html, with a dedicated network page. Unaudited, 51%-attackable mainnet beta; no value claim on the coin.",
    active: "index.html",
    body: stubBody("blochscan.html"),
    staticCsp: true,
    extraHead: `<meta http-equiv="refresh" content="2; url=index.html">\n`,
  },
];

for (const p of pages) {
  fs.writeFileSync(path.join(OUT, p.file), page(p));
  console.log("wrote explorer/" + p.file);
}
