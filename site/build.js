#!/usr/bin/env node
/*
 * Postern Labs — static site generator.
 * Emits seven fully self-contained HTML pages (all CSS inlined, zero JS,
 * zero external requests). Run:  node site/build.js
 */
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const OUT = __dirname;

/* ============================================================
   Shared stylesheet — the instrument-panel family.
   Deck navy/ink + one copper-amber accent. Dark default, light honored.
   ============================================================ */
const CSS = `
:root {
  --font-ui:   -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --font-mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;

  /* dark (default) — graphite / ink */
  --bg:        #161e2a;
  --bg-glow:   #1b2430;
  --surface:   #1f2836;
  --surface-2: #243040;
  --surface-3: #2c3a4c;
  --border:    #2e3d4f;
  --border-hi: #41546b;
  --text:      #eef2f6;
  --text-dim:  #a9b6c4;
  --muted:     #7e8da0;

  --brass:     #c07f45;
  --brass-hi:  #d9995c;
  --brass-dim: #8f5a28;
  --brass-ink: #131922;

  --warn-bg:   #231a10;
  --warn-bord: #6e5426;
  --ok:        #6fae7d;
  --danger:    #ea6a62;

  color-scheme: dark light;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg:        #f4f7fa;
    --bg-glow:   #e8edf2;
    --surface:   #ffffff;
    --surface-2: #eef2f6;
    --surface-3: #e1e8f0;
    --border:    #ccd6e0;
    --border-hi: #a7b7c8;
    --text:      #1b2430;
    --text-dim:  #46566a;
    --muted:     #5a6b7d;

    --brass:     #8f5a28;
    --brass-hi:  #7a4b1f;
    --brass-dim: #b87333;
    --brass-ink: #f4f7fa;

    --warn-bg:   #fbf3e7;
    --warn-bord: #c9a06a;
    --ok:        #3c7a4c;
    --danger:    #b23830;
  }
}

* { margin: 0; padding: 0; box-sizing: border-box; }
html { scroll-behavior: auto; }
@media (prefers-reduced-motion: no-preference) {
  html { scroll-behavior: smooth; }
  a, .card, .btn { transition: color .15s ease, background-color .15s ease, border-color .15s ease; }
}

body {
  font-family: var(--font-ui);
  background: var(--bg);
  color: var(--text);
  line-height: 1.6;
  font-size: 1rem;
  -webkit-font-smoothing: antialiased;
}

.skip {
  position: absolute; left: -9999px; top: 0;
  background: var(--brass); color: var(--brass-ink);
  padding: .5rem 1rem; z-index: 100; font-weight: 600;
}
.skip:focus { left: 0; }

a { color: var(--brass-hi); text-decoration-color: var(--brass-dim); text-underline-offset: 3px; }
a:hover { color: var(--text); }
code, .mono { font-family: var(--font-mono); font-size: .92em; }
code {
  background: var(--surface-2); border: 1px solid var(--border);
  border-radius: 4px; padding: .08em .38em; color: var(--text-dim);
  overflow-wrap: anywhere;
}
pre {
  background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
  padding: 1rem 1.2rem; overflow-x: auto; font-family: var(--font-mono);
  font-size: .85rem; line-height: 1.55; color: var(--text-dim); margin: 1rem 0;
}
pre code { background: none; border: none; padding: 0; }

/* ---------- header ---------- */
.site-head {
  border-bottom: 1px solid var(--border);
  background: var(--bg-glow);
}
.site-head .inner {
  max-width: 68rem; margin: 0 auto; padding: .9rem 1.25rem;
  display: flex; align-items: center; gap: 1.5rem; flex-wrap: wrap;
}
.wordmark {
  display: inline-flex; align-items: center; gap: .6rem;
  font-weight: 700; letter-spacing: .14em; font-size: .95rem;
  color: var(--text); text-decoration: none; text-transform: uppercase;
}
.wordmark svg { flex: none; }
.wordmark .gate-arch { stroke: var(--brass); }
.wordmark .lab { color: var(--brass); }
.site-head nav { margin-left: auto; display: flex; gap: .25rem 1.1rem; flex-wrap: wrap; }
.site-head nav a {
  font-size: .82rem; letter-spacing: .06em; text-transform: uppercase;
  color: var(--text-dim); text-decoration: none; padding: .25rem 0;
  border-bottom: 2px solid transparent;
}
.site-head nav a:hover { color: var(--text); }
.site-head nav a[aria-current="page"] { color: var(--brass-hi); border-bottom-color: var(--brass); }

/* ---------- honest-beta ribbon ---------- */
.beta-ribbon {
  background: var(--warn-bg); border-bottom: 1px solid var(--warn-bord);
  padding: .65rem 1.25rem; text-align: center;
  font-size: .86rem; color: var(--text);
}
.beta-ribbon strong { color: var(--brass-hi); letter-spacing: .05em; }
.beta-ribbon a { white-space: nowrap; }

/* ---------- layout ---------- */
main { display: block; }
.wrap { max-width: 68rem; margin: 0 auto; padding: 0 1.25rem; }
.narrow { max-width: 46rem; }
section { padding: 3.2rem 0; }
section + section { border-top: 1px solid var(--border); }

.kicker {
  font-size: .74rem; letter-spacing: .26em; text-transform: uppercase;
  color: var(--brass); font-weight: 700; margin-bottom: .8rem;
}
h1 {
  font-size: clamp(1.9rem, 4.6vw, 3.1rem); line-height: 1.12;
  letter-spacing: -.015em; font-weight: 750; margin-bottom: 1rem;
  text-wrap: balance;
}
h2 {
  font-size: clamp(1.35rem, 2.6vw, 1.8rem); line-height: 1.2;
  letter-spacing: -.01em; margin-bottom: .9rem; text-wrap: balance;
}
h3 { font-size: 1.06rem; margin-bottom: .4rem; }
.lede { font-size: 1.14rem; color: var(--text-dim); max-width: 44rem; text-wrap: pretty; }
p + p, .prose ul, .prose ol { margin-top: .9rem; }
.prose { max-width: 46rem; color: var(--text-dim); }
.prose strong, .prose b { color: var(--text); }
.prose ul, .prose ol { padding-left: 1.3rem; }
.prose li + li { margin-top: .45rem; }
.dim { color: var(--text-dim); }
.small { font-size: .86rem; }

/* ---------- hero ---------- */
.hero { padding: 4.2rem 0 3.4rem; background: var(--bg-glow); }
.hero .rule {
  width: 4.5rem; height: 4px; background: var(--brass);
  margin-bottom: 1.6rem; border-radius: 0;
}
.cta-row { display: flex; gap: .8rem; flex-wrap: wrap; margin-top: 1.8rem; }
.btn {
  display: inline-block; padding: .68rem 1.25rem; border-radius: 6px;
  font-weight: 650; font-size: .95rem; text-decoration: none;
  border: 1px solid var(--border-hi); color: var(--text);
}
.btn:hover { border-color: var(--brass); color: var(--brass-hi); }
.btn.primary { background: var(--brass); color: var(--brass-ink); border-color: var(--brass); }
.btn.primary:hover { background: var(--brass-hi); border-color: var(--brass-hi); color: var(--brass-ink); }

/* ---------- warning panel ---------- */
.warnpanel {
  background: var(--warn-bg); border: 1px solid var(--warn-bord);
  border-left: 4px solid var(--brass); border-radius: 8px;
  padding: 1.3rem 1.5rem; margin: 1.5rem 0; max-width: 52rem;
}
.warnpanel h2, .warnpanel h3 { color: var(--brass-hi); font-size: 1.02rem; letter-spacing: .04em; text-transform: uppercase; }
.warnpanel p { color: var(--text); margin-top: .55rem; font-size: .95rem; }
.warnpanel ul { margin: .55rem 0 0 1.2rem; font-size: .95rem; }
.warnpanel li + li { margin-top: .35rem; }

/* ---------- cards ---------- */
.grid { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fill, minmax(16rem, 1fr)); margin-top: 1.6rem; }
.card {
  background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
  padding: 1.15rem 1.25rem; display: flex; flex-direction: column; gap: .45rem;
}
.card:hover { border-color: var(--brass-dim); }
.card h3 { display: flex; align-items: baseline; gap: .5rem; flex-wrap: wrap; }
.card p { color: var(--text-dim); font-size: .92rem; flex: 1; }
.card .badges { display: flex; gap: .4rem; flex-wrap: wrap; margin-top: .2rem; }

.badge {
  display: inline-block; font-size: .68rem; font-weight: 700;
  letter-spacing: .08em; text-transform: uppercase;
  padding: .14rem .5rem; border-radius: 4px; border: 1px solid var(--border-hi);
  color: var(--text-dim); white-space: nowrap;
}
.badge.built    { color: var(--ok); border-color: var(--ok); }
.badge.proto    { color: var(--brass-hi); border-color: var(--brass-dim); }
.badge.design   { color: var(--muted); border-style: dashed; }
.badge.unaud    { color: var(--danger); border-color: var(--danger); }
.badge.byok     { color: var(--brass-hi); border-color: var(--brass-dim); }

/* ---------- two-panel compare ---------- */
.compare { display: grid; gap: 1.2rem; grid-template-columns: repeat(auto-fit, minmax(19rem, 1fr)); margin-top: 1.8rem; }
.panel {
  border: 1px solid var(--border); border-radius: 12px; overflow: hidden;
  background: var(--surface);
}
.panel header {
  padding: 1rem 1.4rem; border-bottom: 1px solid var(--border);
  background: var(--surface-2);
}
.panel.owned header { border-top: 3px solid var(--brass); }
.panel.commons header { border-top: 3px solid var(--muted); }
.panel header .tag { font-size: .72rem; letter-spacing: .2em; text-transform: uppercase; color: var(--brass); font-weight: 700; }
.panel.commons header .tag { color: var(--muted); }
.panel header h3 { font-size: 1.25rem; margin-top: .25rem; }
.panel .body { padding: 1.1rem 1.4rem 1.4rem; }
.panel ul { list-style: none; }
.panel li {
  padding: .55rem 0 .55rem 1.4rem; position: relative;
  color: var(--text-dim); font-size: .94rem;
  border-bottom: 1px solid var(--border);
}
.panel li:last-child { border-bottom: none; }
.panel li::before { content: "▸"; position: absolute; left: 0; color: var(--brass); }
.panel.commons li::before { color: var(--muted); }
.panel li strong { color: var(--text); }

/* ---------- stack diagram ---------- */
.stack { margin: 2rem 0 0; max-width: 52rem; }
.stack .layer {
  border: 1px solid var(--border-hi); border-radius: 10px;
  padding: 1rem 1.3rem; background: var(--surface);
}
.stack .layer.base { border-style: dashed; background: transparent; }
.stack .layer .t { font-size: .72rem; letter-spacing: .18em; text-transform: uppercase; font-weight: 700; color: var(--brass); }
.stack .layer.base .t { color: var(--muted); }
.stack .layer p { font-size: .9rem; color: var(--text-dim); margin-top: .3rem; }
.stack .join {
  text-align: center; color: var(--muted); font-size: .78rem;
  padding: .45rem 0; font-family: var(--font-mono);
}

/* ---------- tables ---------- */
.tablewrap { overflow-x: auto; margin-top: 1.4rem; border: 1px solid var(--border); border-radius: 10px; }
table { border-collapse: collapse; width: 100%; font-size: .92rem; min-width: 34rem; }
th, td { text-align: left; padding: .7rem 1rem; border-bottom: 1px solid var(--border); vertical-align: top; }
th { font-size: .74rem; letter-spacing: .12em; text-transform: uppercase; color: var(--muted); background: var(--surface-2); }
tr:last-child td { border-bottom: none; }
td { color: var(--text-dim); }
td strong { color: var(--text); }

/* ---------- demo videos ---------- */
.videos { display: grid; gap: 1.5rem; grid-template-columns: repeat(auto-fit, minmax(19rem, 1fr)); margin-top: 1.6rem; }
.videos figure { margin: 0; min-width: 0; }
.videos video {
  display: block; width: 100%; max-width: 100%; height: auto;
  border: 1px solid var(--border); border-radius: 10px; background: #000;
}
.videos figcaption { margin-top: .6rem; color: var(--text-dim); }
.videos figcaption strong { color: var(--text); }

/* ---------- manifesto film ---------- */
.film { margin: 1.6rem 0 .9rem; border: 1px solid var(--border); border-radius: 12px; overflow: hidden; background: #000; max-width: 54rem; }
.film video { display: block; width: 100%; height: auto; }

/* ---------- steps / definition rows ---------- */
.defrow { display: grid; grid-template-columns: minmax(9rem, 13rem) 1fr; gap: .4rem 1.5rem; padding: 1rem 0; border-bottom: 1px solid var(--border); }
.defrow:last-of-type { border-bottom: none; }
.defrow dt { font-weight: 650; color: var(--text); }
.defrow dd { color: var(--text-dim); font-size: .95rem; }
@media (max-width: 40rem) { .defrow { grid-template-columns: 1fr; } }

/* ---------- footer ---------- */
.site-foot {
  border-top: 1px solid var(--border); margin-top: 3rem;
  background: var(--bg-glow); padding: 2.4rem 0 3rem;
  font-size: .85rem; color: var(--muted);
}
.site-foot .cols { display: grid; gap: 2rem; grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr)); }
.site-foot h4 { font-size: .72rem; letter-spacing: .18em; text-transform: uppercase; color: var(--text-dim); margin-bottom: .6rem; }
.site-foot p + p { margin-top: .6rem; }
.site-foot nav a { display: block; color: var(--text-dim); text-decoration: none; padding: .15rem 0; }
.site-foot nav a:hover { color: var(--brass-hi); }
.site-foot .legal { margin-top: 2rem; padding-top: 1.4rem; border-top: 1px solid var(--border); }

/* Vestnik node-setup assistant (the one interactive widget on the site). */
.vestnik { border: 1px solid var(--border); border-radius: 10px; overflow: hidden; margin-top: 1.2rem; background: var(--panel, rgba(255,255,255,.02)); }
.vestnik .vk-head { display: flex; align-items: center; gap: .6rem; padding: .8rem 1rem; border-bottom: 1px solid var(--border); }
.vestnik .vk-dot { width: .55rem; height: .55rem; border-radius: 50%; background: var(--brass-hi); flex: 0 0 auto; }
.vestnik .vk-title { font-weight: 600; }
.vestnik .vk-scope { color: var(--text-dim); font-size: .85rem; margin-left: auto; }
.vk-log { max-height: 26rem; overflow-y: auto; padding: 1rem; display: flex; flex-direction: column; gap: .7rem; }
.vk-msg { max-width: 92%; padding: .6rem .8rem; border-radius: 9px; line-height: 1.5; white-space: pre-wrap; word-wrap: break-word; }
.vk-msg.vk-user { align-self: flex-end; background: var(--brass-hi); color: #1a1305; }
.vk-msg.vk-bot { align-self: flex-start; background: rgba(255,255,255,.05); border: 1px solid var(--border); }
.vk-msg.vk-sys { align-self: center; color: var(--text-dim); font-size: .85rem; background: none; border: none; text-align: center; max-width: 100%; }
.vk-msg code { background: rgba(0,0,0,.25); padding: .05rem .3rem; border-radius: 4px; }
.vk-msg pre { background: rgba(0,0,0,.35); padding: .6rem .8rem; border-radius: 6px; overflow-x: auto; margin: .4rem 0; }
.vk-msg pre code { background: none; padding: 0; }
.vk-form { display: flex; gap: .5rem; padding: .8rem 1rem; border-top: 1px solid var(--border); }
.vk-input { flex: 1; background: rgba(0,0,0,.25); color: var(--text); border: 1px solid var(--border); border-radius: 7px; padding: .55rem .7rem; font: inherit; resize: none; }
.vk-input:focus { outline: none; border-color: var(--brass-hi); }
.vk-send { background: var(--brass-hi); color: #1a1305; border: none; border-radius: 7px; padding: 0 1rem; font: inherit; font-weight: 600; cursor: pointer; }
.vk-send:disabled { opacity: .5; cursor: default; }
.vk-note { padding: .1rem 1rem 1rem; color: var(--text-dim); font-size: .8rem; }
`;

/* ============================================================ */

const NAV = [
  ["index.html", "Home"],
  ["postern-vs-bloch.html", "Postern & Bloch"],
  ["products.html", "Products"],
  ["downloads.html", "Downloads"],
  ["run-a-node.html", "Run a node"],
  ["migration.html", "SHA-256 migration"],
  ["snapshot.html", "Snapshot sync"],
  ["pool.html", "Pool"],
  ["asic.html", "ASIC"],
  ["releases.html", "Releases"],
  ["security.html", "Security"],
  ["/explorer/", "Explorer"],
  ["disclaimer.html", "Disclaimer"],
  ["acknowledgments.html", "Acknowledgments"],
];

const GLYPH = `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" aria-hidden="true"><path class="gate-arch" d="M5 22V11a7 7 0 0 1 14 0v11"/><path class="gate-line" d="M12 4v18" stroke-width="1.1"/></svg>`;

function header(active) {
  const links = NAV.map(
    ([href, label]) =>
      `<a href="${href}"${href === active ? ' aria-current="page"' : ""}>${label}</a>`
  ).join("\n      ");
  return `<a class="skip" href="#main">Skip to content</a>
<header class="site-head">
  <div class="inner">
    <a class="wordmark" href="index.html">${GLYPH}<span>Postern&nbsp;<span class="lab">Labs</span></span></a>
    <nav aria-label="Site">
      ${links}
    </nav>
  </div>
</header>
<div class="beta-ribbon" role="note" aria-label="Mainnet beta status warning">
  <strong>MAINNET BETA.</strong> Unaudited · <strong>difficulty-driven k-ramp</strong> (k=4 now, rising with hashrate — a structural filter, not a security claim) · very few nodes, low hashrate, 51%-attackable · not a security · for evaluation —
  <strong>not to protect real secrets yet</strong>. <a href="disclaimer.html">Full disclaimer&nbsp;→</a>
</div>`;
}

const FOOTER = `<footer class="site-foot">
  <div class="wrap">
    <div class="cols">
      <div>
        <h4>Postern Labs</h4>
        <p>Privacy &amp; security products, sold the honest way — the BlackBerry model, on permissive Linux, built on an ownerless post-quantum commons.</p>
        <p>No tracking. No analytics. This site makes zero network requests beyond its own pages.</p>
      </div>
      <div>
        <h4>Site</h4>
        <nav aria-label="Footer">
          <a href="index.html">Home</a>
          <a href="postern-vs-bloch.html">Postern &amp; Bloch-SIS-PoW</a>
          <a href="products.html">Products</a>
          <a href="downloads.html">Downloads</a>
          <a href="run-a-node.html">Run a node</a>
          <a href="/explorer/">Explorer</a>
          <a href="disclaimer.html">Disclaimer &amp; legal</a>
          <a href="acknowledgments.html">Acknowledgments &amp; homage</a>
          <a href="blochprotocol.html">The blochprotocol.com domain</a>
          <a href="https://t.me/posternlabs" rel="noopener">Community · Telegram</a>
        </nav>
      </div>
      <div>
        <h4>Standing disclosures</h4>
        <p>The underlying protocol runs a <strong>mainnet beta</strong> — <strong>unaudited</strong> (audit contracted, not done), nascent, <strong>low-hashrate and 51%-attackable</strong>. The Module-SIS gate is now a <strong>difficulty-driven k-ramp</strong> (v0.1.0-alpha2): k=4 today, rising 5→6→7→8 as the network's own difficulty grows, easing back if hashrate falls — the Bitcoin model. The ramp is a <em>structural</em> filter, <strong>not a security claim</strong>: real security is cumulative SHAKE-256 hashcash work — hashrate × time. Nothing here is a certified security product yet.</p>
        <p>The coin is <strong>not a security and not an asset</strong>. No token sale, no listing effort, no price. Disclosed in full: a 17% founder premine (10-year cliff, 40-year vest), structurally passive.</p>
      </div>
    </div>
    <p class="legal">MIT / Apache-2.0, per crate — no copyleft embedded in the products. The Bloch-SIS-PoW protocol is ownerless and is not a Postern Labs product; it lives at <code>gitlab.com/blochsispow-group/BlochSISPoW-project</code> (shown as text on purpose — there is no official site to link to). <strong>Postern Labs holds no ownership of, representation of, or prerogative over the protocol</strong>, and for that reason maintains <strong>no website for Bloch-SIS-PoW</strong> (including <code>blochprotocol.com</code>) — <a href="blochprotocol.html">read the full statement</a>.</p>
  </div>
</footer>`;

/* ============================================================
   Content-Security-Policy for the generated pages.

   These pages run ZERO JavaScript and load ZERO external
   subresources — only same-origin <video> (/media/*.mp4) and
   an inline <style> block plus a handful of static inline
   style="" attributes. So the policy can be strict:

     - default-src 'none'      deny everything not named below
     - script-src  'none'      there is no JS at all
     - style-src   sha256(...) the <style> block and every distinct
                               inline style="" value are pinned by hash
                               (computed here from the exact bytes we
                               emit, so they can never drift), which
                               lets us drop 'unsafe-inline'. 'unsafe-hashes'
                               is required only so a hash may apply to a
                               style="" *attribute* (CSP Level 3).
     - img-src     'self'      no images ship today; 'self' still allows a
                               same-origin favicon without permitting remote
     - media-src   'self'      the demo videos are same-origin
     - font-src    'none'      system font stacks only; nothing is fetched
     - connect-src 'none'      no fetch/XHR/WebSocket. The R2 download links
                               are <a href> navigations, NOT connect-src, so
                               they keep working.

   CSP reduces injection surface; it is not "security" by itself.

   NOTE: frame-ancestors is INERT when delivered via <meta> — browsers
   honor it only from an HTTP response header. It is listed for intent;
   the real clickjacking defense (frame-ancestors / X-Frame-Options) must
   be set as a header by whatever emits public/_headers. upgrade-insecure-
   requests IS honored in <meta> and is kept as hygiene.
   ============================================================ */
function cspHash(source) {
  return "'sha256-" + crypto.createHash("sha256").update(source, "utf8").digest("base64") + "'";
}

function cspMeta(inlineMarkup, opts = {}) {
  const styleAttrs = new Set();
  const re = /style="([^"]*)"/g;
  let m;
  while ((m = re.exec(inlineMarkup))) styleAttrs.add(m[1]);
  const styleSrc = [
    "style-src",
    cspHash(CSS),
    ...(styleAttrs.size ? ["'unsafe-hashes'", ...[...styleAttrs].map(cspHash)] : []),
  ].join(" ");
  // By default every page is ZERO-JS (script-src 'none', connect-src 'none').
  // A page may opt in to inline scripts (each pinned by hash) + same-origin
  // fetch by passing opts.scripts — used ONLY by the node-setup assistant on
  // run-a-node, which posts to the same-origin /api/node-helper function.
  const scripts = opts.scripts || [];
  // opts.externCsp = { script:[urls], connect:[urls], img:[urls] } — external
  // hosts allowed on ONE page only. Used solely by the /products campaign
  // landing for the opt-in (consent-gated) Google Ads conversion tag. Every
  // other page stays default-src 'none' with no external hosts.
  const ext = opts.externCsp || {};
  const scriptParts = [
    ...scripts.map(cspHash),
    ...(ext.script || []),
  ];
  const scriptSrc = scriptParts.length ? "script-src " + scriptParts.join(" ") : "script-src 'none'";
  const connectParts = [
    ...(scripts.length || (ext.connect && ext.connect.length) ? ["'self'"] : []),
    ...(ext.connect || []),
  ];
  const connectSrc = connectParts.length ? "connect-src " + connectParts.join(" ") : "connect-src 'none'";
  const imgSrc = "img-src " + ["'self'", ...(ext.img || [])].join(" ");
  const csp = [
    "default-src 'none'",
    scriptSrc,
    styleSrc,
    imgSrc,
    "media-src 'self'",
    "font-src 'none'",
    connectSrc,
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "upgrade-insecure-requests",
  ].join("; ");
  return `<meta http-equiv="Content-Security-Policy" content="${csp}">`;
}

function page({ file, title, desc, active, body, scripts, externCsp }) {
  const head = header(active);
  const cspTag = cspMeta(head + body + FOOTER, { scripts, externCsp });
  const scriptTags = (scripts || []).map((s) => `<script>${s}</script>`).join("\n");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
${cspTag}
<meta name="description" content="${desc}">
<meta name="color-scheme" content="dark light">
<title>${title}</title>
<style>${CSS}</style>
</head>
<body>
${head}
<main id="main">
${body}
</main>
${FOOTER}
${scriptTags}
</body>
</html>
`;
}

/* ============================================================
   Reusable fragments
   ============================================================ */

const HONEST_PANEL = `<div class="warnpanel" role="note">
  <h3>Honest status — read before anything else</h3>
  <ul>
    <li><strong>Everything here is pre-production.</strong> The Rust product <strong>cores</strong> are built and test-verified. The <strong>OS images have started to exist</strong>: the x86_64 node and desktop ISOs are <strong>built, hosted, and release-signed</strong> — the <strong>node ISO now QEMU/TCG-boots to a login prompt (boot log recorded, grader rc=0)</strong>; the <strong>desktop ISO's QEMU boot is still pending, and a physical-hardware boot is further out</strong>; the mobile image (aarch64, PinePhone / Mobile NixOS) is now <strong>built, hosted, and release-signed, but not yet boot-tested on any platform</strong> — it has not been booted on QEMU aarch64 or on hardware, so it is the least-proven of the three. The UIs and cloud/enterprise editions remain designs and reference prototypes. <strong>Hosting a signed image is not attestation, and built is not booted — we don't claim otherwise.</strong> Each item is labelled with its exact status wherever it appears.</li>
    <li>The underlying protocol now runs a <strong>mainnet beta — a designation, not a security claim</strong>. As of node v0.1.0-alpha2 the fixed k=8 Module-SIS gate is <strong>retired</strong>: the gate is a <strong>difficulty-driven k-ramp</strong> — k=4 today, rising 5→6→7→8 as the network's own ASERT difficulty (the on-chain hashrate proxy) sustains above spaced thresholds, and easing back if hashrate falls (the Bitcoin model). Raising k adds <strong>no cryptographic hardness</strong> at β=q/16 — the ramp is a structural/throughput filter, <strong>not a security claim</strong>, and no security is claimed. Real security is <strong>cumulative SHAKE-256 hashcash work — hashrate × time</strong>. A brand-new node can <strong>sync from genesis again</strong> under the ramp, or use the <strong>signed snapshot</strong> as an optional one-command fast-sync. The network is <strong>nascent: very few nodes, low hashrate → 51%-attackable</strong>. It is <strong>unaudited</strong> — a third-party audit is contracted but <strong>not done yet</strong>, and the concrete-security analysis and IACR ePrint are still outstanding.</li>
    <li><strong>The coin is not a security and not an asset.</strong> No token sale, no listing effort, no market-making, no price. Disclosed in full: a <strong>17% founder premine</strong> (10-year cliff, 40-year vest), structurally passive.</li>
    <li><strong>Do not use any of this to protect real secrets yet.</strong> It is a public beta for evaluation, feedback, and reproduction of our claims.</li>
  </ul>
</div>`;

const badge = (cls, label) => `<span class="badge ${cls}">${label}</span>`;
const B_BUILT = badge("built", "core: built · tests pass");
const B_PROTO = badge("proto", "reference prototype");
const B_DESIGN = badge("design", "design / spec");
const B_UNAUD = badge("unaud", "unaudited");
const B_ISO_QEMU  = badge("built",  "node iso: built · signed · QEMU/TCG boots to login");
const B_ISO_GDM   = badge("built",  "iso: built · hosted + signed · QEMU boot pending");
const B_IMG_MOBILE= badge("proto",  "img: built · hosted + signed · not yet boot-tested (QEMU or hardware)");
const B_APK_REPO  = badge("proto",  "3 signed apks · repo live · non-attestable · never device-booted");
const B_BYOK      = badge("byok",    "bring your own key");
const B_NOTSHIP   = badge("design",  "designed · reference prototype · not shipping");
const B_LIVE      = badge("built",   "live");
const B_POROG     = badge("proto",   "StrongBox key-attest skeleton · DPC isolation design-only · not shipping");
const B_PROPOSED  = badge("design",  "name proposed · pending trademark clearance");
const B_MERGED    = badge("built",   "merged · not yet deployed");

/* Inline key glyph in the GLYPH idiom — inherits currentColor, themes automatically. */
const KEY_GLYPH = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><circle cx="8" cy="9" r="4.6"/><path d="M11.3 12.2 20 21"/><path d="M17 18l2.2-2.2M15 16l1.6-1.6"/></svg>`;

/* Public download host for the signed x86_64 Postern OS release artifacts (v0.1). */
const OS_BASE = "https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev";
const OS_MINISIGN_KEY = "RWTSe98wfKKHuVRDnywuQmH/cMyP/HNuD/hFFLQeKdQeAHENliqJpmKs";
/* Public host + base path for the published, signed postmarketOS/Alpine apk repo. */
const REPO_BASE = "https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev/pmos/postern";
const APK_KEY = "builder-6a52d247";

function card(name, oneliner, badges) {
  return `<article class="card">
  <h3>${name}</h3>
  <p>${oneliner}</p>
  <div class="badges">${badges.join(" ")}</div>
</article>`;
}

/* ============================================================
   PAGE: Home
   ============================================================ */

const HOME = `
<div class="wrap" style="padding-top:1.1rem">
  <div role="note" style="border:1px solid var(--brass);border-left:5px solid var(--brass);background:rgba(180,140,60,.14);border-radius:8px;padding:1.05rem 1.2rem;line-height:1.55;margin-bottom:.9rem">
    <strong style="color:var(--brass-hi)">⛏️ Bloch is migrating to SHA-256 proof-of-work.</strong>
    A new node <strong>cannot sync from genesis</strong>: ~95% of block bodies were pruned everywhere and are unrecoverable, so joining today means trusting a downloaded database rather than verifying the chain. The migration is a <strong>new chain carrying every balance over</strong>, bound to a published snapshot commitment — <strong>coins are not affected</strong>, and signatures stay ML-DSA-65&nbsp;&#8214;&nbsp;Falcon-1024, so post-quantum protection of your keys is unchanged.
    <div class="small dim" style="margin-top:.55rem;border-top:1px solid var(--border);padding-top:.5rem">
      Said plainly: a small SHA-256 chain is <strong>cheap to attack with rented hashrate</strong>, and the current chain is not exposed that way. FFG finality is the answer and <strong>is not ready yet</strong> — committee at height 250,000, activation at 500,000. The window between genesis and activation is <strong>not yet covered</strong>, and that is an open question, not a solved one. <strong>Nothing is launched.</strong>
      &nbsp;→&nbsp; <a href="migration.html"><strong>Read the full status →</strong></a>
    </div>
  </div>
  <div role="note" style="border:1px solid var(--border);border-left:5px solid var(--accent, #4a7);border-radius:8px;padding:.9rem 1.2rem;line-height:1.55;margin-bottom:.9rem">
    <strong>📱 Postern is live on mobile.</strong> The full app in your phone's browser — wallet (real post-quantum keygen &amp; signing in WASM), node status, vault, encrypted backup and more. Add it to your home screen, no store. Unaudited beta, software keystore, zero-value.
    &nbsp;→&nbsp; <a href="/apps/postern/"><strong>Open Postern →</strong></a>
  </div>
  <div role="note" style="border:1px solid var(--brass);border-left:5px solid var(--brass);background:rgba(180,140,60,.11);border-radius:8px;padding:1rem 1.2rem;line-height:1.55">
    <strong style="color:var(--brass-hi)">🛰️ Run a node — new step-by-step setup guide.</strong>
    Six copy-paste steps — install prerequisites, <code>cargo build --release</code>, verify the <strong>signed snapshot</strong> (fresh nodes bootstrap from the snapshot, never genesis on the pruned network), first run, confirm you're converging over RPC, and optionally mine — plus honest troubleshooting (sync deadlocks, the classification/stall fix, gossip saturation).
    &nbsp;→&nbsp; <a href="/Bloch-Node-Setup-Guide.pdf"><strong>Node Setup Guide (PDF) →</strong></a> &nbsp;·&nbsp; <a href="run-a-node.html">Run a node →</a>
    <div class="small dim" style="margin-top:.55rem;border-top:1px solid var(--border);padding-top:.5rem">
      <strong>Node stuck around blue_score 395,897?</strong> That is a known depth-bounded-classification bug (not your setup). The fix — an exact interval-reachability index — is written and on the public branch <code>feat/reachability-durable</code>, <strong>UNAUDITED</strong>, with its live gate <strong>OFF</strong>: upgrading the binary alone changes nothing until the project publishes a coordinated activation height. Step-by-step for operators: <a href="/Bloch-Reachability-Upgrade-Steps.pdf"><strong>Reachability Upgrade Steps (PDF) →</strong></a>
    </div>
  </div>
</div>
<section class="hero">
  <div class="wrap">
    <div class="rule" aria-hidden="true"></div>
    <p class="kicker">Postern Labs · public beta</p>
    <p style="margin:0 0 .9rem"><a href="releases.html" style="display:inline-block;font-size:.82rem;padding:.25rem .75rem;border:1px solid var(--brass);border-radius:999px;color:var(--brass-hi);text-decoration:none">🆕 Release · Bloch node v0.1.0-alpha3 — finality fix + ASERT re-anchor →</a></p>
    <p style="margin:-.5rem 0 1rem;font-size:.88rem;color:var(--text-dim);max-width:44rem">Running a node? <strong>v0.1.0-alpha3</strong> fixes two consensus bugs the k-ramp exposed once block production un-choked: a finality checkpoint <strong>unit fix</strong> (nodes were freezing on ingest — they converge again) and a height-switched <strong>ASERT re-anchor</strong> so difficulty can track real hashrate instead of being capped at 4× genesis forever. Both are backward-safe (historical blocks validate byte-for-byte — no fork); the Module-SIS gate stays the <strong>difficulty-driven k-ramp</strong> from alpha2. <a href="releases.html" style="color:var(--brass-hi)">See the release →</a></p>
    <h1>Privacy &amp; security products, sold the honest way.</h1>
    <p class="lede">Postern Labs builds <strong>owned, rebranded</strong> privacy and security products — a secrets vault, post-quantum file drop, a messenger, passkeys, metadata scrub, a panic lock, a wallet, voice tools, an app store, and a reproducible OS — on top of an <strong>ownerless, post-quantum protocol it does not own</strong>. You pay Postern for protection, support, and provable integrity — never for a coin.</p>
    <div class="cta-row">
      <a class="btn primary" href="downloads.html">Get the beta</a>
      <a class="btn" href="postern-vs-bloch.html">Postern ≠ Bloch — read why</a>
    </div>
  </div>
</section>

<section aria-labelledby="uphold-h">
  <div class="wrap">
    <div style="border:1px solid var(--brass);border-left:5px solid var(--brass);background:rgba(201,162,39,.07);border-radius:12px;padding:1.5rem 1.6rem">
      <p class="kicker" id="uphold-h" style="color:var(--brass-hi)">Run a node · a Ulysses contract for the digital age</p>
      <h2 style="margin:.15rem 0 .55rem">Run a node. Uphold the commitment.</h2>
      <p class="lede" style="margin:0 0 1.1rem">Mine the <strong>ownerless, post-quantum base</strong> from Postern Desktop — <strong>not to profit</strong>, but to uphold a <strong>pre-commitment</strong> to privacy and security as fundamental rights. Like a people binding itself through a <strong>constitution</strong>, the ownerless, permissionless base is a <strong>self-binding commitment device</strong> — a technological <em>Ulysses contract</em> in <a href="acknowledgments.html">Jon Elster's</a> sense — that no future authority, and <strong>not even the founder</strong>, can revoke. <em>From the people, for the people</em> — <strong>We, the People</strong>.</p>
      <figure style="margin:0 auto;max-width:46rem">
        <video controls playsinline preload="metadata" poster="/media/postern-run-a-node-and-mine-poster.png" style="width:100%;max-width:100%;border:1px solid var(--border);border-radius:10px;background:#000">
          <source src="/media/postern-run-a-node-and-mine.mp4" type="video/mp4">
        </video>
        <figcaption class="small dim" style="margin-top:.7rem"><strong>Step-by-step, narrated</strong> — open Run&nbsp;a&nbsp;node, point at the <code>bloch</code> binary, tick <strong>Mine (Module-SIS PoW)</strong>, Start, watch blocks seal, Stop. <strong>Participation, not a purchase:</strong> this is a <strong>zero-value, pre-mainnet testnet</strong>; mining yields <strong>no sellable reward</strong>. <strong>BLCH is worthless by design and is not a security.</strong> Honest limit: the desktop node mines Module-SIS PoW and serves RPC locally, but <strong>cannot yet fully sync or produce blocks on the live mainnet</strong> — local / testnet / reference mining. <strong>Reference prototype, unaudited.</strong> The walkthrough is captured in the labeled browser preview (simulated node). Read <a href="acknowledgments.html">“We, the People” →</a></figcaption>
      </figure>
    </div>
  </div>
</section>

<section aria-labelledby="nodevid-h">
  <div class="wrap">
    <p class="kicker" id="nodevid-h">Run a node · snapshot sync</p>
    <h2>Set up a Bloch node in about three minutes.</h2>
    <figure style="margin:1.2rem auto 0;max-width:46rem">
      <video controls playsinline preload="metadata" poster="/media/bloch-node-setup-v3-poster.png" style="width:100%;max-width:100%;border:1px solid var(--border);border-radius:10px;background:#000">
        <source src="/media/bloch-node-setup-v3.mp4" type="video/mp4">
        <track kind="subtitles" srclang="en" label="English" default src="/media/bloch-node-setup-v3.vtt">
      </video>
      <figcaption class="small dim" style="margin-top:.6rem"><strong>Snapshot sync — set up a Bloch node in ~3 min</strong> · narrated · English captions. The written steps on <a href="snapshot.html">Snapshot sync</a> and <a href="run-a-node.html">Run a node</a> are authoritative. Unaudited research chain; the coin has no value.</figcaption>
    </figure>
  </div>
</section>

<section aria-label="Motto" style="text-align:center;padding:2.6rem 0 0.6rem">
  <div class="wrap">
    <p style="font-size:1.18rem;line-height:1.5;letter-spacing:.005em;color:var(--text-dim);max-width:40rem;margin:0 auto">When mathematics and language communicate to foster privacy.</p>
    <p aria-hidden="true" style="font-size:2.1rem;color:var(--brass);margin:.55rem 0 0;line-height:1">&pi;</p>
  </div>
</section>

<section aria-labelledby="film-h">
  <div class="wrap">
    <p class="kicker" id="film-h">Why Postern</p>
    <h2>A protocol tied to the mast.</h2>
    <figure class="film">
      <video src="/media/why-postern-v3.mp4" controls muted autoplay loop playsinline preload="metadata">
        <track kind="captions" src="/media/why-postern-v3.vtt" srclang="en" label="English" default>
      </video>
    </figure>
    <p class="prose small dim">Freedom, property, privacy — why Postern was built, drawn from the founder's essay on pre-commitment (Ulysses at the mast), Locke on property, and privacy as a constitutional penumbra. English narration (unmute) + captions. <strong>*</strong> The <strong>Bloch protocol</strong> is ownerless — no owner, no board. <strong>Postern Labs</strong> is a company, and <strong>has an owner</strong>. It is a vision piece, not a claim — everything remains pre-mainnet and unaudited.</p>
  </div>
</section>

<section aria-labelledby="honest-h">
  <div class="wrap">
    <p class="kicker" id="honest-h">The part most launch pages hide</p>
    <h2>This is a beta launch, and we say exactly what that means.</h2>
    ${HONEST_PANEL}
    <p class="prose small">Every claim on this site is audit-gated: if a thing isn't true yet, we phrase it as the plan. The full text lives on the <a href="disclaimer.html">disclaimer page</a>.</p>
  </div>
</section>

<section aria-labelledby="model-h">
  <div class="wrap">
    <p class="kicker" id="model-h">The model</p>
    <h2>Owned products ⟂ ownerless protocol.</h2>
    <div class="prose">
      <p>Think Bitcoin and the businesses built around it. The base protocol — <strong>Bloch-SIS-PoW</strong>, a post-quantum, pure-PoW BlockDAG — is a neutral commons: <strong>no owner, no foundation, no official site, no token sale</strong>. It is software plus a documented RPC/API surface, and nothing more. Anyone runs it; anyone builds on it.</p>
      <p><strong>Postern Labs is one builder among many</strong> on that neutral base — a company, with products it owns and a name deliberately rebranded away from “Bloch”. It sells the BlackBerry thing: protection, support, and integrity you can verify, on permissive Linux.</p>
    </div>
    <div class="stack" aria-label="Architecture: Postern products on top of the ownerless protocol">
      <div class="layer">
        <span class="t">Postern Labs — owned products, rebranded</span>
        <p>Vault · Courier · Messenger · Keys · Hygiene · Panic Lock · Seal Companion · Wallet · Postern OS · the apps — permissively licensed, sold for the protection.</p>
      </div>
      <div class="join">│ consumes the protocol via its public RPC / API — nothing privileged │</div>
      <div class="layer base">
        <span class="t">Bloch-SIS-PoW — ownerless protocol</span>
        <p>SHAKE-256 hashcash PoW (Module-SIS gate) · Falcon‖ML-DSA · GhostDAG-Q · the coin. No owner, no curator, no official site or explorer. Just the protocol.</p>
      </div>
    </div>
    <p class="prose small" style="margin-top:1.2rem">This distinction matters enough that it has <a href="postern-vs-bloch.html">its own page</a>.</p>
  </div>
</section>

<section aria-labelledby="suite-h">
  <div class="wrap">
    <p class="kicker" id="suite-h">The suite</p>
    <h2>A tour of what's in the workshop.</h2>
    <p class="prose">The Rust cores below are <strong>built and test-verified</strong>; the front-ends are <strong>reference prototypes</strong>; everything is <strong>unaudited</strong>. Honest labels on every card — the full catalog is on the <a href="products.html">products page</a>.</p>
    <div class="grid">
      ${card("Postern Vault", "A secrets / password vault, sealed at rest with the one canonical seal (XChaCha20-Poly1305 + Argon2id).", [B_BUILT, B_UNAUD])}
      ${card("Postern Courier", "Serverless person-to-person file drop: ML-KEM-1024 payload seal over an ephemeral Tor onion service.", [B_BUILT, B_UNAUD])}
      ${card("Vestnik", "The messenger — Slavic <em>вестник</em>, ‘herald’ (renamed from ‘Messenger’ to steer clear of Meta's mark). The Megolm E2EE core (via vodozemac, Apache-2.0) now drives a real, offline-testable Matrix client — login/sync/room-tier/tier-gated send with PQ-sealable saved-session custody — behind a desktop pane. Live homeserver contact is user-action-only, never in CI; Megolm is classical (not PQ) and the homeserver sees the social graph.", [B_BUILT, B_UNAUD])}
      ${card("Panic Lock", "A panic button that instantly re-locks and destroys nothing.", [B_BUILT, B_UNAUD])}
      ${card("Postern Keys", "A passkey / FIDO2 credential core for the permissive-license world.", [B_BUILT, B_UNAUD])}
      ${card("Postern Hygiene", "Scrubs the document metadata nobody fixes — OOXML, ODF, JPEG.", [B_BUILT, B_UNAUD])}
      ${card("Postern Svitok — encrypted office suite (in design)", "An <strong>encrypted office suite</strong> (свиток, ‘scroll’) — deliberately <strong>not</strong> named after the Word/Excel/PowerPoint/Office marks; ‘office’ is used only as a plain descriptor. It gives <strong>.docx / .pptx / .xlsx-compatible</strong> editing by <strong>aggregating unmodified LibreOffice</strong> (MPL — never forked) under a Postern shell: documents are <strong>sealed at rest by default</strong> with the one canonical seal (postern-core), scrubbed on export (Hygiene) and sanitized on import (Quarantine). <strong>In design / scaffold</strong>: the seal-at-rest + panic-evict session core is started and tested; the LibreOffice-aggregate editor is planned. Honest limit — an inherent, <strong>non-zero plaintext-while-editing window</strong> (minimized via secured scratch / no-swap / secure-delete / Panic-Lock eviction; never claimed zero). Name pending trademark clearance.", [B_DESIGN, B_PROPOSED, B_UNAUD])}
      ${card("Seal Companion", "The attestation verifier: self-audit and peer-verify, so you check our claims instead of trusting them. It now validates a <strong>genuine AWS SEV-SNP attestation report</strong> end-to-end (VLEK→ASVK→ARK chain to AMD's pinned root, nonce-bound) against <strong>real AMD Milan silicon</strong> — an unaudited reference verifier; verified-against-real-hardware is not audited/production.", [B_BUILT, B_UNAUD])}
      ${card("Postern Wallet", "Post-quantum hybrid wallet (Falcon‖ML-DSA), diversified addresses, on-device key vault — on the unaudited, 51%-attackable mainnet beta; the coins carry no value claim.", [B_BUILT, B_PROTO, B_UNAUD])}
      ${card("Porog — Android container", "The <em>door</em> between two worlds (a proposed name, pending trademark clearance; the <em>porog</em> / threshold of the Izbushka tale): a hardened, self-enrolled managed-profile workspace on stock Android — StrongBox key-attestation skeleton + the shared managed-profile DPC. A scaffold, not shipping; key-attested device, not measured-boot workspace; hardened, not anonymous; a rooted host defeats it. Never “Postern OS”.", [B_DESIGN, B_PROTO, B_UNAUD])}
      ${card("NoporIS — the bridge", "The <em>bridge</em> between two worlds (the Kalinov crossing): a dual-persona layer that joins your personal side and a second, Google-Play-enabled persona on one device. The Google side is honestly the <strong>less-private</strong> side (it phones home to Google) — NoporIS sells <strong>separation, not privacy</strong>, and respects Google/Android licenses (no GMS redistribution, no Play-Integrity circumvention). A concept scaffold; name pending trademark clearance.", [B_DESIGN, B_UNAUD])}
    </div>
    <p class="prose small" style="margin-top:1.2rem">For the deep read, engineers and auditors can pull the <a href="/Postern-Technical-Whitepaper.pdf">Technical Whitepaper (PDF)&nbsp;↓</a> and the <a href="/Postern-Audit-Readiness-Dossier.pdf">Audit-Readiness Dossier (PDF)&nbsp;↓</a> — code-derived, every UNAUDITED / not-booted marker intact. Neither is an audit.</p>
    <div class="cta-row">
      <a class="btn" href="products.html">See the full catalog</a>
    </div>
  </div>
</section>

<section aria-labelledby="roadmap-h">
  <div class="wrap">
    <p class="kicker" id="roadmap-h">Roadmap · designed, not shipping</p>
    <h2>Next: Kalinov Bridge — private, post-quantum backups for your Postern OS files.</h2>
    <article class="card" style="max-width:52rem">
      <h3>Kalinov Bridge <span class="small dim">— Postern backups on Filecoin</span> ${B_DESIGN} ${B_UNAUD}</h3>
      <p><strong>Bloch-SIS-PoW + Postern Labs + Filecoin — privacy and post-quantum security for your Postern OS files.</strong> The plan: private <strong>user backups</strong> stored on <strong>Filecoin</strong>, but sealed client-side with the <strong>Postern seal</strong> (XChaCha20-Poly1305) <em>before</em> anything leaves the sealed base — <strong>Filecoin only ever sees ciphertext</strong>, and the keys never leave your device. <strong>Post-quantum integrity and authenticity</strong> come from Bloch cryptography: a <strong>SHAKE-256</strong> manifest signed with <strong>ML-DSA-65&nbsp;‖&nbsp;Falcon</strong>, anchored to the ownerless Bloch base as an ordinary <strong>zero-value on-chain commitment</strong> (“DATA0”).</p>
      <p class="small dim">Honest status: the <strong>full Kalinov Bridge</strong> — the ML-DSA-65&nbsp;‖&nbsp;Falcon-signed SHAKE-256 manifest anchored to the base — is still <strong>roadmap / planned</strong>. What exists <em>today</em> is a first slice of the path as an <strong>unaudited reference prototype</strong>: the <a href="downloads.html#desk-h">Encrypted Backup pane in Postern Desktop</a> seals a file locally, writes the SHAKE-256 “DATA0” integrity anchor, and does a <strong>real upload of the sealed ciphertext to Filecoin</strong> (real CID; only ciphertext leaves the device). That is a prototype, <strong>not audited and not production</strong> — don't entrust a real backup to it yet. Newer: the <strong>ML-DSA-65&nbsp;‖&nbsp;Falcon-1024 signer over the SHAKE-256 manifest is now implemented and tested at the crate level</strong> (<code>postern-backup-net</code> — an end-to-end test seals, hashes, packages, <strong>signs</strong>, spools and restores a backup, independently verifies <em>both</em> signature halves, and rejects a single tampered byte), still <strong>unaudited</strong>; the on-chain <strong>DATA0 broadcast</strong> and the desktop-pane wiring on top of that signer are <strong>not shipped</strong> yet. Designed ≠ built ≠ booted. It touches the ownerless base only as an ordinary zero-value transaction; BLCH is <strong>not a security</strong> and Postern's revenue never touches the token. Tracked on the <a href="/Postern-Roadmap.md">Postern products roadmap&nbsp;↓</a>.</p>
    </article>
  </div>
</section>

<section aria-labelledby="founder-h">
  <div class="wrap">
    <p class="kicker" id="founder-h">About · the founder</p>
    <h2>Tiago Tenório (“TT”) — Founder &amp; CEO.</h2>
    <div class="prose">
      <p>Tiago Tenório (TT) is the founder and CEO of Postern Labs. He comes from Brazil's payments and fintech sector — a Visa prepaid/third-party ISO agent (2018–2020); founder of the AG47 office and a member of C6 Bank's Conexão C6 program, operating across São Paulo, Goiás, the Federal District, Alagoas and Paraná (2020–2021); a national distribution partner in First Data Corporation's Ignite program for acquiring products and services (2020–2021); PMO lead on a cards project at Havan (2021–2022); and Commercial Director at Avalon Capital, an asset manager (2022). In 2026 he founded Postern Labs to build privacy-first, post-quantum software — and the ownerless Bloch-SIS-PoW protocol its products build on, in which he holds no privileged role beyond a fully disclosed, structurally passive 17% founder premine.</p>
      <p class="small">The companies named above state his prior roles only — none of them endorses, backs, funds, or is affiliated with Postern Labs or Bloch-SIS-PoW.</p>
      <p class="small"><a href="https://www.linkedin.com/in/tiago-tenorio-a028733bb" rel="noopener">Tiago B. de A. Tenório on LinkedIn</a> — an outbound link; this site still loads nothing external and makes no network requests of its own.</p>
    </div>
  </div>
</section>

<section aria-labelledby="never-h">
  <div class="wrap">
    <p class="kicker" id="never-h">Standing commitments</p>
    <h2>What we will never do.</h2>
    <div class="prose">
      <ul>
        <li><strong>Never sell you the coin.</strong> No token sale, no listing effort, no “ecosystem fund”, no yield marketing. Postern's revenue story never touches the token.</li>
        <li><strong>Never overclaim to the people who'd pay for it with their safety.</strong> No product here says “100% private”; every app carries an honest privacy panel.</li>
        <li><strong>Never embed copyleft, never close the source.</strong> MIT / Apache-2.0; the free build is always buildable from source.</li>
        <li><strong>Never ship a security claim before its audit.</strong> Claims for the protocol and for the products are separate, and each is audit-gated.</li>
        <li><strong>No covert surveillance, no tracking</strong> — including this website, which makes zero network calls.</li>
      </ul>
    </div>
    <div class="cta-row">
      <a class="btn primary" href="downloads.html">Try the beta</a>
      <a class="btn" href="disclaimer.html">Read the disclaimer</a>
    </div>
  </div>
</section>
`;

/* ============================================================
   PAGE: Postern vs Bloch
   ============================================================ */

const VS = `
<section class="hero">
  <div class="wrap">
    <div class="rule" aria-hidden="true"></div>
    <p class="kicker">The distinction that everything rests on</p>
    <h1>Postern &amp; Bloch-SIS-PoW are two different things.</h1>
    <p class="lede">One is a company that owns products. The other is an ownerless piece of public infrastructure that nobody owns — including us. Confusing them would be convenient for marketing and corrosive for honesty, so this page exists to make the line unmistakable.</p>
  </div>
</section>

<section aria-labelledby="cmp-h">
  <div class="wrap">
    <h2 id="cmp-h">Side by side</h2>
    <div class="compare">
      <div class="panel owned">
        <header>
          <span class="tag">A company</span>
          <h3>Postern Labs</h3>
        </header>
        <div class="body">
          <ul>
            <li><strong>Owns its products</strong> — vault, courier, messenger, wallet, OS, apps — all rebranded away from “Bloch”.</li>
            <li><strong>Has a website</strong> — this one.</li>
            <li><strong>Sells protection and support</strong> — the BlackBerry model: signed builds, update channels, org deployments, training. Never a coin.</li>
            <li><strong>Permissively licensed</strong> — MIT / Apache-2.0, no copyleft embedded.</li>
            <li><strong>Accountable</strong> — its claims are its own, and each is audit-gated.</li>
          </ul>
        </div>
      </div>
      <div class="panel commons">
        <header>
          <span class="tag">An ownerless protocol</span>
          <h3>Bloch-SIS-PoW</h3>
        </header>
        <div class="body">
          <ul>
            <li><strong>No owner. No foundation. No curator.</strong> Not Postern Labs, not the author of the code.</li>
            <li><strong>No official website, no official explorer, no token sale.</strong> If you find a site claiming to be “the official Bloch site”, it isn't.</li>
            <li><strong>Software + a documented RPC/API surface, and nothing more.</strong> Chain state, blocks, mempool, addresses, submit-tx, attestation.</li>
            <li><strong>Anyone runs it; anyone builds on it.</strong> An explorer on Bloch is like mempool.space on Bitcoin — an independent product, not “Bloch's explorer”.</li>
            <li><strong>Lives in its own repository:</strong> <code>gitlab.com/blochsispow-group/BlochSISPoW-project</code>.</li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</section>

<section aria-labelledby="rel-h">
  <div class="wrap">
    <h2 id="rel-h">The relationship, precisely</h2>
    <div class="prose">
      <p><strong>Postern Labs is one builder among many on a neutral base.</strong> Its products consume the protocol the same way anyone else's would — through the public RPC/API, with no privileged access, no admin keys, no special role in consensus. Think of Bitcoin and the wallets, explorers, and companies built around it: the protocol is public infrastructure; the tools built on it have owners.</p>
      <p><strong>Postern is not the steward of the protocol.</strong> If a community forms to steward Bloch-SIS-PoW, good — but it will not be steered by Postern Labs, and not by the author. The protocol repository stays free of product and site material; the products live here, as independent projects.</p>
      <p>Not everything Postern makes even touches the chain. The OS, the vault, the hygiene scrubber, and the messenger are independent of it; only the wallet and chain-facing tools consume the RPC/API.</p>
    </div>
    <div class="stack" aria-label="Postern products consume the protocol via RPC/API only">
      <div class="layer">
        <span class="t">Postern Labs (owned products, rebranded)</span>
        <p>Privacy/security on permissive Linux — parameterizable, attestable, sold. Wallet and explorer-class tools talk to the chain; the OS and most of the suite don't need it at all.</p>
      </div>
      <div class="join">│ RPC / API — the same public surface available to everyone │</div>
      <div class="layer base">
        <span class="t">Bloch-SIS-PoW (ownerless — RPC/API only)</span>
        <p>SHAKE-256 hashcash PoW (Module-SIS gate) · Falcon‖ML-DSA · GhostDAG-Q · Coherence · the coin. No owner. No curator. No official site or explorer. Just the protocol.</p>
      </div>
    </div>
  </div>
</section>

<section aria-labelledby="build-h">
  <div class="wrap">
    <p class="kicker" id="build-h">Build on the commons</p>
    <h2>Build on Bloch — the base is open to everyone.</h2>
    <div class="prose">
      <p>Because the protocol is ownerless, <strong>anyone can build on it</strong> — and Postern is only one builder. To make that real, we've <strong>published, open-source and permissively licensed</strong>, a set of <strong>client SDKs (TypeScript, Python, and Go)</strong>, a <strong>developer portal</strong>, and an <strong>anchoring framework</strong> for committing data to the chain. These are <strong>live and public</strong> — the SDK clients are one of the few things here that actually ship — but they are <strong>early scaffolding and unaudited</strong>; treat them as a starting point, not a finished platform.</p>
      <p>They talk to the same <strong>public RPC/API</strong> everyone else uses — <strong>no privileged access, no admin keys</strong>. Postern ships them so the ownerless base has tools; it does not make Postern the owner of anything.</p>
    </div>
  </div>
</section>

<section aria-labelledby="agility-h">
  <div class="wrap">
    <p class="kicker" id="agility-h">Protocol evolution · pre-mainnet</p>
    <h2>Protocol agility — landed on the fork, not yet mainnet.</h2>
    <div class="prose">
      <p>A recent consensus bundle landed and merged on the fork and is <strong>test-verified by local / host cargo tests</strong> (79 crypto tests green; remote CI offline). It changes the signed bytes of every transaction, signature, and address. It is <strong>unaudited and pre-mainnet — no security property is claimed</strong>, and the difficulty-driven k-ramp (k=4 today) is a structural filter, not a security claim by itself; the chain stays unaudited.</p>
    </div>
    <dl>
      <div class="defrow">
        <dt>Crypto-agility SUITE-ID envelope</dt>
        <dd>A 4-byte <code>B1 0C</code> + suite-id header on every public key and signature, with a registry: <code>0x0001</code> is today's ML-DSA65‖Falcon-1024 hybrid, <code>0x0002</code> an ML-DSA65-only suite. Falcon is <strong>removable in principle via the suite registry — not removed</strong>; the shipped default is still the <code>0x0001</code> hybrid. Not a security property. <span class="badge built">landed · test-verified on host</span> <span class="badge unaud">unaudited · pre-mainnet</span></dd>
      </div>
      <div class="defrow">
        <dt>Chain-ID in the tx sighash</dt>
        <dd>A fixed domain constant + 4-byte chain-id (Mainnet <code>0xB10C_0001</code> / Testnet <code>0xB10C_0002</code>) folded into the signed preimage, so <strong>testnet↔mainnet and cross-fork replay is now domain-separated in the signed bytes</strong>, even with identical outpoints. A correctness / hygiene fix — <strong>not</strong> a security guarantee; the difficulty-driven k-ramp is a structural filter, not a security guarantee. <span class="badge built">landed · test-verified on host</span> <span class="badge unaud">unaudited · pre-mainnet</span></dd>
      </div>
      <div class="defrow">
        <dt>Activation-height guard</dt>
        <dd>A release tripwire (behind an empty <code>mainnet</code> feature) that <strong>fails any mainnet artifact still carrying the <code>1_000_000</code> placeholder height</strong>. It blocks shipping the placeholder; it does not secure a live chain. <span class="badge built">landed · test-verified on host</span></dd>
      </div>
    </dl>
  </div>
</section>

<section aria-labelledby="why-h">
  <div class="wrap">
    <h2 id="why-h">Why the hard separation</h2>
    <div class="prose">
      <p><strong>Because a gatekeeper is a promoter-shaped entity.</strong> A protocol with an owner who grants privileges, runs the official site, and shapes the market is exactly what the “not a security” posture cannot survive. So the protocol has no owner — and Postern's name contains no “Bloch”, and Postern's revenue story never touches the token in any sentence.</p>
      <p><strong>And because the users who need this most deserve the truth.</strong> Postern's products earn their keep as security and privacy products — you use them for the protection, not to mine or hold a token.</p>
    </div>
  </div>
</section>

<section aria-labelledby="status2-h">
  <div class="wrap">
    <p class="kicker" id="status2-h">Repeated here on purpose</p>
    <h2>The same honest status applies on this page.</h2>
    <div class="warnpanel" role="note">
      <h3>Mainnet beta, unaudited, not a security</h3>
      <p>The protocol now runs a <strong>mainnet beta — a designation, not a security claim</strong>. As of node v0.1.0-alpha2 the fixed k=8 gate is <strong>retired</strong>: the Module-SIS gate is a <strong>difficulty-driven k-ramp</strong> — k=4 today, rising 5→6→7→8 as the network's own difficulty grows and easing back if hashrate falls (the Bitcoin model). Raising k adds <strong>no cryptographic hardness</strong> at β=q/16 — the ramp is a structural filter, <strong>not a security claim by itself</strong>, and no security is claimed. Security is cumulative SHAKE-256 hashcash work — hashrate × time. A new node can <strong>sync from genesis</strong> or use the optional <strong>signed snapshot</strong> fast-sync; the network is <strong>nascent, low-hashrate, and 51%-attackable</strong>; and the software is <strong>unaudited</strong> — the third-party audit is contracted but not done, and the concrete-security analysis and IACR ePrint are still outstanding.</p>
      <p><strong>The coin is not a security and not an asset.</strong> There is no token sale, no listing effort, and no price. The one fact a skeptic should weigh against “ownerless” is disclosed in full and kept visible on purpose: a <strong>17% founder premine</strong> (10-year cliff, 40-year vest), structurally passive. Do not attach value to the coin.</p>
    </div>
    <div class="cta-row">
      <a class="btn" href="disclaimer.html">Full disclaimer</a>
      <a class="btn" href="index.html">Back to Postern Labs</a>
    </div>
  </div>
</section>
`;

/* ============================================================
   PAGE: Products
   ============================================================ */

/* AI-interactions / bring-your-own-key disclosure. Reuses .panel.owned,
   .tablewrap, .warnpanel, KEY_GLYPH, B_BYOK — no new CSS. The disclosure
   copy is the verbatim honesty-advisor text (rounds nothing up). */
const AI_INTERACTIONS = `
<section aria-labelledby="ai-h">
  <div class="wrap">
    <p class="kicker">AI interactions · bring your own key</p>
    <h2 id="ai-h">Some apps talk to Claude — with your key, not ours.</h2>
    <div class="prose">
      <p>A few of the apps use Claude to do their work. <strong>Sotto</strong>, <strong>Vedetta</strong>, and <strong>Tolmach</strong> need a key to function; <strong>Postern Store</strong> and <strong>Sarto</strong> take one only for an optional feature; <strong>Izbushka</strong> and <strong>Ezekiel 1</strong> never touch the network at all. Wherever a key is used, you supply your <strong>own Anthropic (Claude) key</strong> and the app calls Anthropic directly from your browser — <strong>nothing is proxied through a Postern server</strong> (the one exception, Tolmach's subscription tier, is called out below). The AI path is optional; the parts of each app that don't need Claude work with no key at all.</p>
    </div>

    <div class="panel owned">
      <header>
        <span class="tag">${KEY_GLYPH} how the AI concierge is wired</span>
        <h3>Bring your own key</h3>
        <p style="margin-top:1.2rem">${B_BYOK} ${B_UNAUD}</p>
      </header>
      <div class="body">
        <p><strong>How the AI works — and what leaves your machine.</strong> These apps talk to Claude using <strong>your own Anthropic API key</strong>. The key is entered in your browser and stored in this browser's <code>localStorage</code>; on the apps that offer it, you can <strong>seal the key at rest</strong> with a passphrase (AES-256-GCM), so the browser holds only ciphertext until you unlock it for a session. <strong>There is no Postern server in this path</strong> — nothing we run ever sees your key or your prompts.</p>
        <p><strong>But "your own key" is not "private AI," and it is not "local AI."</strong> Every message you send is transmitted from your browser <strong>directly to Anthropic</strong> (<code>api.anthropic.com</code>) and is processed on <strong>Anthropic's servers</strong>, under <strong>Anthropic's terms</strong>. Using your own key changes <em>who is billed</em> (you, on your Anthropic account) and <em>who contracts with Anthropic</em> (you) — it does <strong>not</strong> keep your prompt on your machine. <strong>Sending a prompt to Claude is sending your data to a third party.</strong> If a message would be unsafe for Anthropic to see, do not send it.</p>
        <p>What this design <em>does</em> give you: no extra middleman between you and Anthropic, no Postern account, no Postern-side logging, and a single readable HTML file you can inspect to confirm the only place your prompt goes is <code>api.anthropic.com</code>.</p>
      </div>
    </div>

    <h3 style="margin-top:2.2rem">Which apps use it</h3>
    <div class="tablewrap">
      <table>
        <thead><tr><th>App</th><th>AI role</th><th>Key path</th></tr></thead>
        <tbody>
          <tr><td><strong>Sotto</strong></td><td>Voice assistant — Claude is the brain.</td><td>${B_BYOK}</td></tr>
          <tr><td><strong>Vedetta</strong></td><td>Markets lookout — AI analysis over your holdings.</td><td>${B_BYOK} <span class="small dim">· optional Finnhub key for near-real-time US quotes</span></td></tr>
          <tr><td><strong>Tolmach</strong></td><td>Interpreter and meeting-minutes.</td><td>${B_BYOK} <span class="small dim">· subscription tier planned (not enabled today)</span></td></tr>
          <tr><td><strong>Postern Store</strong></td><td>Natural-language catalog search (opt-in).</td><td>${B_BYOK} <span class="small dim">· optional — the catalog works keyless</span></td></tr>
          <tr><td><strong>Sarto</strong></td><td>Onboarding configurator (spoken/typed intent → profile).</td><td>${B_BYOK} <span class="small dim">· optional — the manual editor works keyless and offline</span></td></tr>
          <tr><td><strong>Izbushka / Yagabona</strong></td><td>Task portal — authors signed manifests; makes no calls.</td><td><span class="small dim">none — <code>connect-src 'none'</code></span></td></tr>
          <tr><td><strong>Ezekiel 1</strong></td><td>Governance console — runs entirely offline.</td><td><span class="small dim">none — <code>connect-src 'none'</code></span></td></tr>
        </tbody>
      </table>
    </div>

    <div class="warnpanel" role="note">
      <h3>The honest caveats</h3>
      <p><strong>Voice input goes to a third party too — and it is a <em>different</em> third party.</strong> Voice uses your browser's built-in speech recognition (the Web Speech API). In Chrome and Chromium-based browsers this <strong>streams your microphone audio to Google's servers</strong> for transcription — it is <strong>not</strong> on-device, and this is the one data flow that does <strong>not</strong> go to Anthropic. It cannot be restricted by our page's network policy, because the browser performs it. Voice is <strong>off until you turn it on</strong>, is <strong>push-to-talk</strong> (the mic is live only while you hold the button — except Tolmach's Listen/Minutes modes, where the mic stays hot for as long as the mode runs), and we keep no recordings and add no telemetry. Once audio reaches Google it is handled under Google's terms, outside our control. <strong>Want nothing audio to leave the machine? Type instead — typed input stays local until you send it to Claude.</strong> Spoken replies are generated on your device.</p>
      <p><strong>Vedetta also talks to your market-data providers.</strong> To fetch quotes it connects to the providers you choose from a fixed allowlist (CoinGecko, Frankfurter, Finnhub, Yahoo Finance). <strong>Each quote lookup reveals the symbol you searched to that provider</strong>, and your Finnhub key is sent to Finnhub. So Vedetta's honest destination list is: <strong>Anthropic (your prompts), your chosen quote providers (your symbols), and — if you use voice — your browser's speech vendor (your audio).</strong> Never described as fully private.</p>
      <p><strong>Tolmach is bring-your-own-key only, for now.</strong> A hosted <em>Subscription</em> tier — where Claude usage would be billed to the operator instead of you, so your messages would pass through a Postern/operator proxy that sees the prompt text in transit — is <strong>planned as a future evolution, not enabled today</strong>. When it ships it will be clearly labelled the <strong>less-private</strong> option; the bring-your-own-key path will always remain and be the recommended one; and it will never be marketed as equally private.</p>
    </div>
  </div>
</section>
`;

const PRODUCTS = `
<section class="hero">
  <div class="wrap">
    <div class="rule" aria-hidden="true"></div>
    <p class="kicker">The Postern Store — presented honestly</p>
    <h1>The catalog, with its labels on.</h1>
    <p class="lede">Every entry below carries an honest status badge. <strong>Built</strong> means the Rust core compiles and its tests pass. <strong>Reference prototype</strong> means a working front-end that demonstrates the design. <strong>Design / spec</strong> means a documented plan, not running software. And <strong>everything</strong> — no exceptions — is <strong>unaudited</strong>.</p>
    <div style="margin-top:1.4rem" class="cta-row">
      <span class="badge built">core: built · tests pass</span>
      <span class="badge proto">reference prototype</span>
      <span class="badge design">design / spec</span>
      <span class="badge unaud">unaudited</span>
    </div>
    <p class="prose small" style="margin-top:1.2rem">Where an OS image exists, its badge states exactly how far it has been proven: <em>built</em> is not <em>booted</em>, and a <em>QEMU boot</em> is not a <em>hardware boot</em>.</p>
  </div>
</section>

<section aria-labelledby="cores-h">
  <div class="wrap">
    <p class="kicker" id="cores-h">The cores</p>
    <h2>Product cores — built, test-verified, unaudited.</h2>
    <p class="prose">The verified Rust foundations (<code>crates/postern-*</code>). All of them seal with one canonical primitive set: an XChaCha20-Poly1305 AEAD seal and an Argon2id KDF, so one core to audit protects everything.</p>
    <div class="grid">
      ${card("Postern Wallet", "Post-quantum hybrid wallet (Falcon‖ML-DSA), diversified addresses, on-device key vault. Talks to the ownerless protocol via public RPC — now the unaudited mainnet beta (nascent, 51%-attackable), so the coins it holds carry no value claim and are not for investment.", [B_BUILT, B_PROTO, B_UNAUD])}
      ${card("Postern Vault", "A secrets / password vault, sealed at rest. Reuses the wallet's key-wrapping design (StrongBox / Secure Enclave class) — highest infrastructure reuse in the portfolio. On desktop it now has a <strong>live macOS-Keychain vault path</strong> (the wrap key held in the OS keystore). Unaudited.", [B_BUILT, B_UNAUD])}
      ${card("Postern Courier", "Serverless person-to-person file drop: the payload is sealed with ML-KEM-1024 (FIPS-203) and delivered over an ephemeral Tor onion service. No server ever holds your file.", [B_BUILT, B_UNAUD])}
      ${card("Vestnik", "The Megolm E2EE core (via vodozemac — the Matrix project's Rust Olm/Megolm, Apache-2.0, audited by Least Authority in 2022; that audit covers vodozemac, not this product) now backs a real, offline-testable Matrix client: login / sync / room-tier / tier-gated-E2EE-send with PQ-sealable saved-session custody, wired end-to-end behind a desktop pane. Live login/sync/send stay ignore-gated (never booted in CI); Megolm is classical, not post-quantum, and the homeserver still sees the social graph.", [B_BUILT, B_UNAUD])}
      ${card("Postern Seal Companion", "The user-facing attestation verifier: self-audit and peer-verify. Turns the Seal from invisible infrastructure into something you can see and use — verify Postern's claims instead of trusting them. It now validates a <strong>genuine AWS SEV-SNP attestation report</strong> end-to-end — the full VLEK→ASVK→ARK certificate chain to AMD's pinned root, bound to a fresh nonce, proven against <strong>real AMD Milan silicon</strong>. An <strong>unaudited reference verifier</strong>: “verified against real hardware” is not “audited” or “production.”", [B_BUILT, B_UNAUD])}
      ${card("Panic Lock", "A panic button that instantly re-locks: one call seals the vault. It destroys nothing — an ethics decision, not a limitation.", [B_BUILT, B_UNAUD])}
      ${card("Postern Keys", "A passkey / FIDO2 credential core. Identity is the biggest unfilled gap in the permissive-license daily-driver — this is the Apache-side answer. A passphrase-sealed export / import path (carry a credential between machines over the existing sealed blob) is built and test-verified in review — unaudited, not yet deployed.", [B_BUILT, B_UNAUD])}
      ${card("Postern Hygiene", "Document metadata scrubbing for OOXML, ODF, and JPEG — the author fields, revision trails, and EXIF that leak when nothing else does.", [B_BUILT, B_UNAUD])}
    </div>
    <h3 style="margin-top:2.2rem">Under the hood</h3>
    <p class="prose small">Shared plumbing you don't install separately: <strong>Postern Core</strong> (the one canonical seal), <strong>Postern Quarantine</strong> (inbound-document safety — the mirror of Hygiene), <strong>Postern Tor</strong> (in-process Tor via Arti), <strong>Postern Telephony</strong> (carrier SMS/calls surface for Postern OS Mobile), the <strong>Postern SDK</strong> (now the single UniFFI <code>setup_scaffolding!</code> surface over the whole suite for Android / iOS / desktop — exactly-one-scaffolding, CI-checked; the app shells import <code>postern_sdk</code> directly; the SDK now exposes the <strong>real Argon2id KDF Rust-side</strong>, though the HTML app demos such as Chiave still use a PBKDF2 stand-in until they adopt it), <strong>postern-trail</strong> (the one append-only, SHAKE-256 hash-chained audit trail behind Yagabona and Ezekiel 1 — tamper-<em>evident</em>, not tamper-<em>proof</em>), and <strong>postern-policy</strong> (the one shared consent kernel — fail-closed decisions, required grant expiry, revocation-as-never-given, and the honest userland-not-kernel enforcement caveat every surface reuses). All built and test-verified; all unaudited. The mobile signer tracks the node's signed bytes per network; the byte-identity golden re-pin is still pending. The <strong>mobile↔desktop integration that turns the phone into an offline signer for the desktop (phone-as-signer)</strong> has a <strong>working v1 reference implementation (real interop)</strong> — QR + spoken-code pairing over a post-quantum-hybrid channel, a replay-proof sign-request protocol whose keys structurally cannot cross the wire, a WalletCore-backed mobile signer, and <strong>monotonic per-grant revoke</strong> (“revoke this laptop”). A <strong>v2 message shape is forward-declared but not built</strong>; everything is <strong>unaudited, and the desktop and phone ends are not yet unified on one wire</strong>. It is a reference of the shape, not a shipped feature.</p>
  </div>
</section>

<section aria-labelledby="apps-h">
  <div class="wrap">
    <p class="kicker" id="apps-h">The apps</p>
    <h2>Reference front-ends — self-contained, honest by construction.</h2>
    <p class="prose">Each app is a single self-contained HTML file. Where an AI concierge is offered, you bring your own Claude key — nothing is proxied through us. Every app carries an honest privacy panel, and none of them claims “100% private”.</p>
    <div class="grid">
      ${card("Sotto", "A quiet, privacy-first voice assistant.", [B_PROTO, B_UNAUD])}
      ${card("Vedetta", "A quiet lookout on the markets — voice-driven; your holdings never leave the device.", [B_PROTO, B_UNAUD])}
      ${card("Tolmach", "A private interpreter and meeting-minutes taker.", [B_PROTO, B_UNAUD])}
      ${card("Postern Store", "Say what you need; it parameterizes the search across the catalog. Backed by a self-hosted, F-Droid-style multi-repo <strong>Depot</strong> — a reproducible-build verifier and CRL revocation, so apps are distributed without a gatekeeper.", [B_PROTO, B_UNAUD])}
      ${card("Chiave", "Sign in with your wallet — no email, no account. The postern-sdk now provides a real Argon2id KDF, but this HTML demo still uses a PBKDF2 stand-in until it adopts it.", [B_PROTO, B_UNAUD])}
      ${card("Sarto", "The onboarding configurator — set up your Postern, including transparent (never covert) parental and corporate controls.", [B_PROTO, B_UNAUD])}
      ${card("Consiglio", "The enterprise admin console, now with a real hybrid-PQ (Falcon‖ML-DSA) signature verifier. The server-side authorization now binds every privileged control verb to an authenticated PQ-login session (closing the caller-identity spoofing that previously defeated dual-control) — built and test-verified in review, unaudited and not yet deployed. Full dual-control / separation-of-duties and Chinese-Wall enforcement remains in progress; LGPD/GDPR/CCPA-enabling controls.", [B_PROTO, B_UNAUD])}
      ${card("Yagabona", "Privacy-first scheduled-task agent daemon for Postern OS: a task runs only when you author an Izbushka manifest granting it a scoped, expiring capability. Fail-closed, hash-chained tamper-evident audit — enforced in userland by construction, not an OS sandbox; a rooted host defeats it. Local-only, zero telemetry.", [B_PROTO, B_UNAUD])}
      ${card("Izbushka", "The task portal — the only door into Yagabona: a console that authors signed task manifests and makes no network calls of its own (<code>connect-src 'none'</code>).", [B_PROTO, B_UNAUD])}
      ${card("Ezekiel 1 — Personal", "Parental controls, nothing more: one household, parent → child levels, no tenants, no spying — a child reaching up to a parent is refused. Per-access fail-closed, hash-chained audit; the console runs fully offline. Free forever on mobile; the desktop build is freemium — 2 years free, then a key for updates — and your household's data always stays openable either way.", [B_PROTO, B_UNAUD])}
      ${card("Ezekiel 1 — Business", "Consiglio's access-layer governance engine: nested no-widening layers, Bell-LaPadula levels, Brewer-Nash Chinese walls, tenant isolation — every access evaluated fail-closed in userland, hash-chained tamper-evident audit, no Postern server. Not legal advice: it demonstrates controls that enable compliance, it is not compliance.", [B_PROTO, B_UNAUD])}
      ${card("NoporIS", "The guarded <em>bridge</em> between the Google-Play side and the hardened world. Now unified on one canonical consent kernel (parity-tested), with strict gate-state loading, revoke-all fan-out, and <code>from_persona</code> enforced at the receiver — a managed-profile persona switch that actually drives the daemon. Android bridge tier; reference front-end, unaudited.", [B_PROTO, B_UNAUD])}
      ${card("Porog", "The guarded <em>door</em> into the hardened world — an AOSP managed profile. Collapsed to <strong>one</strong> Kotlin reconcile decision path (golden-vector-pinned, 321 parity checks green); StrongBox key-attestation now <strong>pinned to a real captured attestation cert chain</strong>, with a <code>--mobile</code> verify CLI. Verified on a real device only; Kotlin is compile-correct by inspection here.", [B_PROTO, B_UNAUD])}
      ${card("Sloboda", "The tier where data <em>leaves</em> the sealed base entirely, over a host-side Tor egress rail (a POSIX-sh watcher). By design it is <strong>never Seal-covered and never attested</strong> — and states that plainly in-product.", [B_PROTO, B_UNAUD])}
      ${card("Postern Wallet — mobile", "A touch-first mobile wallet face for the ownerless Bloch base: the screens and the phone-as-signer approve / WYSIWYS flow. A <strong>reference prototype</strong> — a browser software keystore (not the phone's StrongBox / Secure Enclave), a <strong>labelled placeholder</strong> PQ signature (not a real Falcon‖ML-DSA sign), and illustrative balances with the live-node RPC seam disabled. Installs as a <strong>PWA</strong> — add it to your home screen or desktop and it opens full-screen and works offline (<code>connect-src 'self'</code>, same-origin only — still no live node, no external network). Moves <strong>no real funds</strong>.", [B_PROTO, B_UNAUD])}
    </div>
  </div>
</section>

${AI_INTERACTIONS}

<section aria-labelledby="appvid-h">
  <div class="wrap">
    <p class="kicker" id="appvid-h">See them in action</p>
    <h2>Short demos — the real apps, labelled for what they are.</h2>
    <div class="prose">
      <p>Each clip is the <strong>actual app running</strong> (or, for the headless daemons, an honest explainer card), narrated and subtitled. All are <strong>pre-release beta and unaudited</strong>. Where an app offers an AI concierge, you bring your own Claude key and that cloud path is honestly the <strong>less-private</strong> one — nothing is proxied through us (except the clearly-labelled Tolmach subscription tier). Nothing shown is a security claim.</p>
    </div>
    <div class="videos">
      <figure><video controls playsinline muted preload="metadata"><source src="/media/sotto-demo.mp4" type="video/mp4"></video><figcaption class="small"><strong>Sotto</strong> — privacy-first voice assistant (bring-your-own key)</figcaption></figure>
      <figure><video controls playsinline muted preload="metadata"><source src="/media/vedetta-demo.mp4" type="video/mp4"></video><figcaption class="small"><strong>Vedetta</strong> — voice markets lookout; research only, holdings stay on-device</figcaption></figure>
      <figure><video controls playsinline muted preload="metadata"><source src="/media/tolmach-demo.mp4" type="video/mp4"></video><figcaption class="small"><strong>Tolmach</strong> — private interpreter + meeting minutes</figcaption></figure>
      <figure><video controls playsinline muted preload="metadata"><source src="/media/store-demo.mp4" type="video/mp4"></video><figcaption class="small"><strong>Postern Store</strong> — natural-language catalog search (local, no tracking)</figcaption></figure>
      <figure><video controls playsinline muted preload="metadata"><source src="/media/postern-chiave-presentation.mp4" type="video/mp4"></video><figcaption class="small"><strong>Chiave</strong> — sign in with your wallet; no email, no account, no server. Prototype: keys are a browser software keystore, hardware-backed unlock is the labelled goal · unaudited</figcaption></figure>
      <figure><video controls playsinline muted preload="metadata"><source src="/media/sarto-demo.mp4" type="video/mp4"></video><figcaption class="small"><strong>Sarto</strong> — onboarding + transparent (never covert) controls</figcaption></figure>
      <figure><video controls playsinline muted preload="metadata"><source src="/media/postern-consiglio-presentation.mp4" type="video/mp4"></video><figcaption class="small"><strong>Consiglio</strong> — enterprise console: wallet-as-login, RBAC, dual-control / separation-of-duties, Chinese-Wall barriers. Prototype: the hybrid-PQ verify is real; dual-control/SoD and walls are declared-not-yet-runtime-wired · not legal advice</figcaption></figure>
      <figure><video controls playsinline muted preload="metadata"><source src="/media/postern-ezekiel1-presentation.mp4" type="video/mp4"></video><figcaption class="small"><strong>Ezekiel 1</strong> — access-layer governance, personal + business editions: nested layers that never widen their parent, Chinese walls, SHAKE-256 hash-chained audit. Enforced in userland by construction, not an OS/kernel boundary · unaudited</figcaption></figure>
      <figure><video controls playsinline muted preload="metadata"><source src="/media/postern-yagabona-presentation.mp4" type="video/mp4"></video><figcaption class="small"><strong>Yagabona</strong> — the privacy-first scheduled-task daemon: fail-closed Threshold Test, explicit expiring capability grants, hash-chained audit trail. An explainer of the manifest + rules (the daemon is headless); UNBUILT/UNBOOTED on a device · unaudited</figcaption></figure>
      <figure><video controls playsinline muted preload="metadata"><source src="/media/postern-izbushka-presentation.mp4" type="video/mp4"></video><figcaption class="small"><strong>Izbushka</strong> — the task portal, the door into Yagabona: author/grant/schedule tasks, TOML manifests, the cursor-companion mascot. <code>connect-src 'none'</code> — no network; it only authors manifests</figcaption></figure>
    </div>
  </div>
</section>

<section aria-labelledby="plat-h">
  <div class="wrap">
    <p class="kicker" id="plat-h">OS &amp; platform</p>
    <h2>The bigger surfaces — labelled built vs designed.</h2>
    <div class="tablewrap">
      <table>
        <thead><tr><th>Surface</th><th>What it is</th><th>Honest status</th></tr></thead>
        <tbody>
          <tr><td><strong>Postern OS (node appliance)</strong></td><td>A reproducible NixOS image that boots straight into a running node — same inputs, same image. Nix profiles in <code>os/</code>. x86_64 ISO built, hosted, and release-signed; now <strong>QEMU/TCG-boots to a login prompt</strong> (boot log recorded, grader rc=0); hardware boot further out. <a href="downloads.html">Download &amp; verify →</a></td><td>${B_ISO_QEMU} ${B_UNAUD}</td></tr>
          <tr><td><strong>Postern OS — Desktop</strong></td><td>The daily-driver privacy OS: reproducible, hardened, attestable-by-design (hardened GNOME, LUKS, Tor, Postern Browser — its DNS and hardening were recently tightened, still <strong>hardened, not anonymous</strong>, unaudited public beta). x86_64 ISO built, hosted, and release-signed; QEMU boot pending (no boot log published yet); hardware boot further out. <a href="downloads.html">Download &amp; verify →</a></td><td>${B_ISO_GDM} ${B_UNAUD}</td></tr>
          <tr><td><strong>Postern OS — Mobile</strong></td><td>The wallet-first phone OS on Mobile NixOS (PinePhone / aarch64), defined by the <code>os/mobile.nix</code> module (documented build target <code>.#mobile-image</code>). Image is built, hosted, and release-signed — but <strong>not yet boot-tested on QEMU-aarch64 or hardware</strong>: built ≠ booted.</td><td>${B_IMG_MOBILE} ${B_UNAUD}</td></tr>
          <tr><td><strong>Kalinov Bridge</strong> <span class="small dim">— Postern backups on Filecoin</span></td><td>The <em>Kalinov</em> bridge between worlds — a <strong>Bloch ↔ Postern ↔ Filecoin</strong> path for private user backups of Postern OS files: sealed client-side with the <strong>Postern seal</strong> (XChaCha20-Poly1305) <em>before</em> leaving the sealed base, then stored on <strong>Filecoin</strong> as ciphertext (Filecoin never sees plaintext; keys never leave the device). Post-quantum integrity via a <strong>SHAKE-256</strong> manifest signed <strong>ML-DSA-65&nbsp;‖&nbsp;Falcon</strong>, anchored to the ownerless Bloch base as a <strong>zero-value “DATA0” commitment</strong>. <strong>Status:</strong> the <strong>ML-DSA-65&nbsp;‖&nbsp;Falcon signer over the SHAKE-256 manifest is now implemented + tested at the crate level</strong> (<code>postern-backup-net</code>, unaudited — an end-to-end test signs a real backup and verifies both signature halves); the <strong>on-chain DATA0 broadcast + desktop-pane wiring remain roadmap</strong>. A first slice already runs as an <strong>unaudited reference prototype</strong> — the <a href="downloads.html#desk-h">Encrypted Backup pane</a> seals locally, writes the SHAKE-256 “DATA0” anchor, and does a <strong>real Filecoin upload of the sealed ciphertext</strong> (real CID, ciphertext-only). Not audited, not production — no real backup should rely on it yet. Designed ≠ built ≠ booted. <a href="/Postern-Roadmap.md">Roadmap →</a></td><td>${B_DESIGN} ${B_UNAUD}</td></tr>
          <tr><td><strong>Postern for postmarketOS (community edition)</strong></td><td>The non-attestable tier: the app suite + wallet as signed apk packages on stock postmarketOS. Signed only — no reproducibility or attestation claim, software keystore. The apk repo is now live (3 packages); never device-booted.</td><td>${B_APK_REPO} ${B_UNAUD}</td></tr>
          <tr><td><strong>Porog</strong> <span class="small dim">— Postern Container (Android)</span></td><td>The <em>porog</em> is the threshold — the guarded doorstep of the Izbushka hut — the door meant to unite two worlds on the phone you already own: your personal side and a hardened workspace. It has nudged past pure design on one front: a <strong>real StrongBox key-attestation skeleton</strong> now lives in the Android app shell (a hardware-backed X.509 attestation chain). The <strong>defining self-enrolled-DPC / managed-profile isolation and Tor-only egress remain design/spec</strong> (unstarted in code). Bounded honestly: even complete this yields a <strong>key-attested device, not a measured-boot workspace</strong>; it is <strong>hardened, not anonymous</strong>; a <strong>rooted host defeats it</strong>; and it is <strong>never “Postern OS.”</strong> Not shipping. <em>Porog</em> is a <strong>proposed name, pending trademark clearance</strong>.</td><td>${B_PROPOSED} ${B_POROG} ${B_UNAUD}</td></tr>
          <tr><td><strong>NoporIS</strong> <span class="small dim">— the bridge (dual-persona Android)</span></td><td>Where <em>Porog</em> is the <strong>door</strong>, <strong>NoporIS is the <em>bridge</em></strong> (the Kalinov crossing of the tales): a dual-persona layer that joins two worlds on one phone — your personal side and a second, <strong>Google-Play-enabled</strong> persona — so you don't carry two devices. The Google side is honestly the <strong>less-private</strong> side: it phones home to Google, so NoporIS sells <strong>separation, not privacy</strong> on that side, and it <strong>respects Google/Android licenses</strong> (no GMS redistribution — the user brings their own Google install; no SafetyNet/Play-Integrity circumvention — honest labelling instead; Android &amp; Google Play named nominatively only). Reuses <em>Porog</em>'s managed-profile plumbing without forking it; the guarded crossing is deny-by-default, per-capability. A <strong>concept scaffold</strong>, not shipping; a rooted host defeats the separation; <strong>never “Postern OS.”</strong> <em>NoporIS</em> is a <strong>proposed name, pending trademark clearance</strong>.</td><td>${B_PROPOSED} ${B_DESIGN} ${B_UNAUD}</td></tr>
          <tr><td><strong>Cloud edition</strong></td><td>Confidential-VM deployment (SEV-SNP / TDX). The attested path advanced past spec: the <strong>SEV-SNP attestation verifier now validates a genuine AWS SEV-SNP attestation report end-to-end</strong> — the full <strong>VLEK→ASVK→ARK</strong> certificate chain to AMD's pinned root, bound to a fresh nonce, proven against <strong>real AMD Milan silicon</strong> (an <strong>unaudited reference verifier</strong>: “verified against real hardware” is <em>not</em> “audited” or “production”). Alongside it, a <strong>TDX quote parser that stays fail-closed</strong> (it never returns <em>Genuine</em>) and an <code>os/cloud.nix</code> profile (in-guest LUKS-keyed <code>/persist</code>). The <strong>guest-side deployment</strong> — the confidential VM you would actually run — is still <strong>unbuilt and unbooted</strong>: code, a proven verifier, and profiles, not a running, hosted TEE. A <strong>hosted reference-prototype</strong> of the license-verification service is live for inspection at <a href="https://postern-cloud-demo.fly.dev/v1/posture" rel="nofollow noopener">postern-cloud-demo.fly.dev</a> — its <code>/v1/posture</code> endpoint discloses, in its own words, that hosting is <strong>less private than on-device verification</strong> (the operator sees which org checked in and when). No private key is hosted; unaudited staging, not production.</td><td>${B_PROTO} ${B_DESIGN} ${B_UNAUD}</td></tr>
          <tr><td><strong>Business &amp; enterprise editions</strong></td><td>Identity &amp; governance model (wallet-as-login, org controls); Consiglio is its console prototype — now with a real hybrid-PQ verifier (dual-control / separation-of-duties declared but not yet runtime-enforced). Admin console + master→sub licensing (a revocation-list / CRL endpoint now exists as a reference prototype; Dun &amp; Bradstreet KYC remains a documented TODO — DUNS is format-checked only), internal team comms with the compliance-engine prototypes mounted, and the BYOD shield — <a href="#biz-h">detailed below</a>. Only the master-license generator ships today.</td><td>${B_DESIGN} ${B_PROTO}</td></tr>
          <tr><td><strong>Postern Svitok</strong> <span class="small dim">— encrypted office suite (свиток)</span></td><td>An <strong>encrypted office suite</strong> — deliberately <strong>not</strong> named after the Word/Excel/PowerPoint/Office marks (&ldquo;office&rdquo; is a plain descriptor only). It gives <strong>.docx / .pptx / .xlsx-compatible</strong> editing by <strong>aggregating unmodified LibreOffice</strong> (MPL — never forked) under a Postern shell: documents are <strong>sealed at rest by default</strong> with the one canonical seal (<code>postern-core</code>), scrubbed on export (Hygiene) and sanitized on import (Quarantine). <strong>Design / scaffold</strong>: the seal-at-rest + Panic-evict session core is started and tested (crate <code>postern-office</code>); the LibreOffice-aggregate editor is planned. Honest limit — an inherent <strong>non-zero plaintext-while-editing window</strong> (minimized via secured scratch / no-swap / secure-delete / Panic-Lock eviction; never claimed zero). Name pending trademark clearance.</td><td>${B_DESIGN} ${B_PROPOSED} ${B_UNAUD}</td></tr>
        </tbody>
      </table>
    </div>
    <p class="prose small" style="margin-top:1.2rem">Licensing, suite-wide: MIT / Apache-2.0 per crate, no GPL/AGPL embedded anywhere in the products. Ready to try something? Head to <a href="downloads.html">downloads</a> — and read the <a href="disclaimer.html">disclaimer</a> first.</p>
    <p class="prose small" style="margin-top:.6rem"><strong>Two roadmaps.</strong> What comes next lives in two deliberately separate documents. The <a href="/Postern-Roadmap.md">Postern products roadmap (Markdown)&nbsp;↓</a> is the <strong>owned</strong> plan for everything on this page — the suite cores and their Tauri/TUF signed packaging, Vestnik, the Postern OS images, Terem, and the Layer-2 <strong>RWA / BaaS</strong> products that anchor to the ownerless base. The <a href="/Bloch-Roadmap.md">Bloch open protocol items (Markdown)&nbsp;↓</a> is <strong>not</strong> a plan of ours or anyone's: the base is <strong>ownerless</strong> — no owner, no authority, no schedule, no governance, <strong>pure PoW</strong> — just candidate items any node operator or community member may pursue, the way Bitcoin has BIPs. Together they replace the old single "Future Roadmap" PDF that mixed the two layers. Both are honest and unaudited; BLCH is <strong>not a security</strong>, and Postern's revenue never touches the token.</p>
  </div>
</section>

<section aria-labelledby="biz-h">
  <div class="wrap">
    <p class="kicker" id="biz-h">Business &amp; enterprise editions</p>
    <h2>The corporate story — mostly designed, honestly labelled.</h2>
    <div class="prose">
      <p>With <strong>two exceptions</strong>, the business and enterprise editions are <strong>designs and reference prototypes — pre-production, UNAUDITED, not shipping</strong>. The two things that are actually <strong>live</strong> today are the <a href="/license/master">master-license generator</a> and the <a href="postern-vs-bloch.html#build-h">public SDK clients</a>. Everything below is labelled with exactly what it is. <strong>“Adherence-by-design” is a design goal, not a certification</strong>; for the regulated pieces a <strong>legal review is a hard gate</strong> before anything ships.</p>
    </div>
    <figure style="margin:1.6rem 0">
      <video controls playsinline preload="metadata" style="width:100%;max-width:100%;border:1px solid var(--border);border-radius:10px;background:#000"><source src="/media/postern-enterprise.mp4" type="video/mp4"></video>
      <figcaption class="small dim" style="margin-top:.6rem">A ~2.5-minute overview of the business / enterprise edition (English narration, English captions burned in). Almost everything shown is <strong>designed / reference prototype, pre-production, unaudited</strong> — only the master-license generator and the open-source SDK clients are live today. Employer-run tools are <strong>not “fully private”</strong>; the BYOD shield <strong>never touches the personal side</strong>; the mobile↔desktop integration was <strong>designed</strong> when this video was made — a <strong>v1 reference implementation now exists (real interop, with monotonic per-grant revoke); a v2 shape is forward-declared but not built — still unaudited and not wired end-to-end</strong>. Coin is worthless / not a security; billing, if any, is in fiat, never the coin.</figcaption>
    </figure>
    <dl>
      <div class="defrow">
        <dt>Admin console &amp; master→sub licensing</dt>
        <dd>A company with a <strong>DUNS number</strong> generates a <strong>master license</strong> — unlimited users, offline-verified, no telemetry — and splits it into scoped sub-accesses. The <strong>generator is live</strong> at <a href="/license/master">/license/master</a>; the <strong>admin console and its management features are a reference prototype</strong>, not shipping software. The previously-missing <strong>revocation path now exists</strong> as a reference prototype: a published <strong>revocation-list (CRL) endpoint</strong> — an <strong>in-memory reference store</strong>, keyed by a token-signature hash rather than serials, and <strong>not server-signed</strong> (a durable, signed store is the design, not the state today). <strong>Dun &amp; Bradstreet KYC at renewal is still a documented TODO</strong> — the DUNS is <strong>format-checked only</strong> (9 digits), not verified against D&amp;B. The CRL endpoint lives in the licensing service, <strong>merged but not yet deployed</strong> — not a live endpoint. ${B_LIVE} <span class="small dim">— generator</span> ${B_MERGED} <span class="small dim">— CRL endpoint</span> ${B_NOTSHIP} <span class="small dim">— console</span> ${B_UNAUD}</dd>
      </div>
      <div class="defrow">
        <dt>Internal team communication</dt>
        <dd>Org-wide end-to-end-encrypted messaging built on the <strong>Vestnik core</strong>, now with the <strong>compliance-engine prototypes mounted</strong> — retention, DSAR (data-subject-access requests), breach notification, and an admin-actions audit trail. LGPD/GDPR <strong>adherence-BY-DESIGN — not certified</strong> (legal review is a hard gate; these reference-prototype engines are plumbing, not a compliance certificate). Because it is an <strong>employer-run tool it is honestly not “fully private”</strong>: message <strong>bodies are E2EE</strong>, but <strong>metadata is visible to the organization</strong> and <strong>retention is disclosed</strong> — there is <strong>no silent backdoor</strong>, and the employer-visibility wrinkle is stated, not hidden. ${B_NOTSHIP} ${B_UNAUD}</dd>
      </div>
      <div class="defrow">
        <dt>BYOD shield container</dt>
        <dd>Reach the corporate Linux system from a <strong>personal phone</strong>; <strong>leaving the container loses access</strong> to corporate data. Honestly: containment is <strong>by construction — a rooted phone defeats it</strong>; offline revoke is <strong>best-effort</strong>; and it <strong>never surveils the personal side</strong> — it touches corporate data only, that scope is disclosed and employee-visible. LGPD/GDPR BYOD <strong>adherence-by-design, not certified</strong>; legal review is a hard gate. ${B_NOTSHIP} ${B_UNAUD}</dd>
      </div>
      <div class="defrow">
        <dt>Deployment, signed-build channel &amp; SLA support</dt>
        <dd>The <a href="disclaimer.html#d9">§9</a> revenue line: deployment tooling, a signed/notarized build channel, and priority/SLA support. <strong>Reference tooling</strong> — it sells work and assurance, never your data and never the coin. ${B_NOTSHIP} ${B_UNAUD}</dd>
      </div>
      <div class="defrow">
        <dt>Cloud edition (hosted)</dt>
        <dd>An <strong>opt-in, business-only</strong> Postern-hosted option for teams that don't want to self-host — it sells <strong>convenience and ops, not privacy</strong>. Two distinct things: the <strong>Chiostro</strong> confidential-VM profile (a TEE you can <em>verify</em> — its attestation verifier now validates a <strong>genuine AWS SEV-SNP report</strong> end-to-end, VLEK→ASVK→ARK to AMD's pinned root, against <strong>real AMD Milan silicon</strong>; an unaudited reference verifier, not audited/production — plus a fail-closed TDX parser and the <code>os/cloud.nix</code> profile, while the guest VM itself is still <strong>unbuilt and unbooted</strong>) and a <strong>managed-node service</strong> (which <em>promises</em>, does no cryptography). Honestly: <strong>hosting is less private than self-hosting</strong> — a hosted relay carries E2EE message bodies opaquely but sees routing metadata; disclosed up front, "a promise, not a proof". <strong>Personal editions stay local and never move to the cloud</strong> (their own freemium terms are on the pricing tiers above; the cloud option is business-only). Running it makes Postern a <strong>data processor</strong> (a DPA is required); billed in fiat, never the coin. A <strong>hosted reference-prototype</strong> of the managed license-verification endpoint is up for inspection at <a href="https://postern-cloud-demo.fly.dev/v1/posture" rel="nofollow noopener">postern-cloud-demo.fly.dev/v1/posture</a> — it states its own privacy trade-off in plain words and hosts no private key. Staging demo, unaudited, not production. ${B_NOTSHIP} ${B_UNAUD}</dd>
      </div>
    </dl>

    <h3 style="margin-top:2.2rem">The tiers</h3>
    <div class="tablewrap">
      <table>
        <thead><tr><th>Tier</th><th>Who</th><th>Terms</th></tr></thead>
        <tbody>
          <tr><td><strong>Platform, mobile &amp; dev</strong></td><td>Everyone — the free adoption channel</td><td><strong>Free forever</strong> — Postern OS (Mobile / Desktop / Node), Core, the SDK, the Store, the Browser, Terem, Depot, <strong>and every personal app on mobile</strong> (Wallet, Vault, Keys, Courier, Seal, Hygiene, Panic, Vestnik, Tor, Quarantine, Telephony, Encrypted Backup, personal Ezekiel 1, …). No login, no tracking, no telemetry. Running a node is participation, not a purchase. <strong>Free versions may show contextual, no-tracking ads</strong> — chosen only from what's on the current screen, <strong>no profile, no ad/device ID, no third-party ad SDK, no telemetry, nothing leaves the device</strong>, always labeled, and <strong>never</strong> in Panic, Vault decrypt/export, or backup. Surveillance / behavioral / programmatic ads are forbidden.</td></tr>
          <tr><td><strong>Postern Desktop (personal)</strong></td><td>Individuals, on desktop only</td><td><strong>Free for 2 years · then a key.</strong> Postern Desktop <strong>reserves the right to require a license in the future</strong>: each install is free for 24 months, after which a personal key keeps updates and premium features coming. No login, no tracking, no telemetry. The key gates features/updates, <strong>never your own data</strong> — decrypt, read, export, and Panic always work, key or not. The free version may show the same <strong>contextual, no-tracking ads</strong>; <strong>the paid key removes ads</strong>. <strong>Mobile personal apps are unaffected — free forever.</strong></td></tr>
          <tr><td><strong>Business (freemium)</strong></td><td>Small teams — no DUNS needed</td><td>Up to <strong>3 desktops</strong>, free for <strong>2 years</strong>, then a key.</td></tr>
          <tr><td><strong>Corporate (master)</strong></td><td>Companies with a DUNS number</td><td><strong>Unlimited users</strong>, split from one master license. <strong>Free 6-month evaluation</strong> while pricing is being structured; after it a license is required. Any future charge is <strong>fiat, never the coin</strong>; <strong>offline-verified, no telemetry</strong> (we store only your DUNS and the dates).</td></tr>
        </tbody>
      </table>
    </div>
    <p class="prose small" style="margin-top:1.2rem">Consistent with <a href="disclaimer.html#d9">§9 of the disclaimer</a>. Revenue never comes from the coin (worthless, not a security) and never from surveilling the personal user.</p>
  </div>
</section>
`;

/* ============================================================
   PAGE: Downloads
   ============================================================ */

const DOWNLOADS = `
<section class="hero">
  <div class="wrap">
    <div class="rule" aria-hidden="true"></div>
    <p class="kicker">Get the beta</p>
    <h1>Everything ships as source. On purpose.</h1>
    <p class="lede">Postern's integrity story is reproducibility: you build what you run, and the same inputs produce the same artifact. The <strong>x86_64 Postern OS ISOs are now hosted, release-signed, and click-downloadable below</strong> — with their SHA-256 digests and a minisign signature beside them, so you verify before you boot. the <strong>node ISO now QEMU/TCG-boots to a login prompt (boot log recorded)</strong>; the <strong>desktop ISO's QEMU boot is still pending, and a physical-hardware boot is further out</strong>; the aarch64 mobile image is now <strong>built, hosted, and release-signed too — but not yet boot-tested on any platform</strong> (no QEMU-aarch64 or hardware boot), so treat it as the least-proven download. Building from source remains the strongest verification, and it's still here. Here is exactly what you can run today, and how.</p>
    ${HONEST_PANEL}
    <p class="prose small" style="margin-top:1.2rem"><strong>Want to see what's <em>not</em> done yet? Two roadmaps — because the two layers must never blur.</strong> The old single "Future Roadmap" PDF mixed the ownerless protocol and the owned products in one plan; it is <strong>replaced</strong> by two documents. <a href="/Bloch-Roadmap.md">Bloch — open protocol items (Markdown)&nbsp;↓</a> is <strong>not a company plan and has no owner</strong>: the base follows the Bitcoin model — no authority, no schedule, no dates — so it is an honest list of candidate items <strong>any node operator or community member may pursue</strong>, BIP-style: further gate/difficulty tuning beyond the difficulty-driven k-ramp, the third-party audit, the no-shortcut proof and IACR ePrint, a live multi-node WAN network, Coherence (shielded txs — no privacy claim today), and the neutral permissionless tokens / fork / L2 capability. Nobody schedules these; the community may create a foundation someday if it chooses — its prerogative, not Postern's; Postern does not drive the protocol. And the base stays <strong>pure PoW</strong>: BFT and oracles were <strong>removed from base consensus</strong> and stay out — the base's only built-in finality is checkpoint reorg-depth protection, a normal PoW feature, not a gadget and not governance. Distinct from the base, a post-quantum <strong>FFG-BFT finality <em>overlay</em></strong> (hashrate-weighted, anchored as ordinary zero-value transactions — <strong>not</strong> a base-consensus change; coins still do not vote) is a <strong>candidate</strong> item with a declared activation target of block 1,000,000, <strong>not built</strong> (see <a href="blochprotocol.html">the roadmap note</a>). <a href="/Postern-Roadmap.md">Postern — products roadmap (Markdown)&nbsp;↓</a> <strong>is</strong> a real owned plan a company builds and answers for: the apps, the Postern OS images (node / desktop / mobile — the node ISO now QEMU-boots), Vestnik (the messenger, renamed off "Messenger"), the vault / courier / hygiene / keys / seal / panic cores plus Tauri/TUF signed packaging, Terem, and the owned Layer-2 products — <strong>RWA / BaaS</strong> — that anchor to the ownerless base as ordinary transactions. The rule: <em>the base is ownerless; anything with an operator, a service, or a "who runs it?" answer is a Postern product.</em> Everything on both lists is <strong>unaudited</strong>, the chain's gate is the <strong>difficulty-driven k-ramp</strong> (k=4 today — a structural filter, not a security claim by itself), there are no promises and no dates on the ownerless side, and BLCH is <strong>not a security</strong> — Postern's revenue never touches the token.</p>
    <p class="prose small" style="margin-top:.6rem"><strong>Where the protocol is headed — ownership.</strong> Two documents on Bloch-SIS-PoW's intended path to community ownership: the <a href="/Bloch-Community-Transition-Model.pdf">Community Transition Model (PDF)&nbsp;↓</a> — a Bitcoin-model handover where <strong>coins do not vote</strong>, changes flow by voluntary node/miner adoption, and the founder <strong>steps fully away</strong> — and a <a href="/Bloch-Community-Transition-Letter.pdf">letter to the community (PDF)&nbsp;↓</a>. These concern the <strong>ownerless protocol</strong>, not Postern's products; they are <strong>letters of intent</strong> — nothing is decentralized or safe yet, and BLCH is <strong>not a security</strong>.</p>
    <p class="prose small" style="margin-top:.6rem"><strong>For engineers &amp; auditors — the deep technical read.</strong> Two code-derived documents written for adversarial senior review: the <a href="/Postern-Technical-Whitepaper.pdf">Technical Whitepaper (PDF)&nbsp;↓</a> — a dense, honest description of every layer (the two crypto hubs, each product core, the NixOS/pmOS profiles, phone-as-signer, and the Bloch-SIS-PoW base), with every <em>planned / scaffold / UNAUDITED / not-booted</em> marker left in — and the <a href="/Postern-Audit-Readiness-Dossier.pdf">Audit-Readiness Dossier (PDF)&nbsp;↓</a>, the packaging that unblocks a contracted external audit (full primitive inventory, threat model, in-scope vs out). Neither is an audit or an assurance: <strong>everything remains a reference prototype and unaudited</strong>, and the coin is <strong>worthless by design</strong>.</p>
    <p class="prose small" style="margin-top:.6rem"><strong>For developers — build on the ownerless protocol.</strong> The <a href="/Bloch-RPC-API.pdf">Bloch RPC/API reference (PDF)&nbsp;↓</a> documents the protocol's <strong>entire</strong> public surface (the JSON-RPC methods) — because Bloch-SIS-PoW is <strong>ownerless</strong>, that surface is all there is, and <strong>anyone can run a node and build on it</strong> (an explorer, a wallet, a service; there is no official API host). <a href="/Postern-Two-Layers.pdf">The Two Layers (PDF)&nbsp;↓</a> draws the line between the <strong>ownerless base</strong> and the <strong>owned Postern products</strong> — including where <strong>RWA / BaaS</strong> sit — and <a href="/Postern-Roadmap-Status.pdf">Roadmap &amp; Status (PDF)&nbsp;↓</a> is the honest done / scaffold / blocked snapshot.</p>
    <p class="prose small" style="margin-top:.6rem"><strong>For a first read — the institutional presentation.</strong> An overview of who Postern Labs is, the owned-products&#8869;ownerless-protocol model, the product cores and apps, the OS surfaces, and the standing disclosures — the same honest labels as everywhere else (<em>built / reference prototype / design / unaudited</em>), nothing softened for a deck. Two formats, two languages: the <strong>slide deck</strong> (11 slides, to present) — <a href="/Postern-Labs-Institutional-Presentation-EN.pdf">English (PDF)&nbsp;↓</a> · <a href="/Postern-Labs-Institutional-Presentation-PT.pdf">Português (PDF)&nbsp;↓</a> — and the <strong>detailed document</strong> (a denser one-page-per-section read) — <a href="/Postern-Labs-Institutional-Overview-EN.pdf">English (PDF)&nbsp;↓</a> · <a href="/Postern-Labs-Institutional-Overview-PT.pdf">Português (PDF)&nbsp;↓</a>.</p>
  </div>
</section>

<section aria-labelledby="web-h">
  <div class="wrap">
    <p class="kicker" id="web-h">1 · The web apps</p>
    <h2>Self-contained HTML — open the file, that's the install.</h2>
    <div class="prose">
      <p>Each app is one self-contained HTML file — <strong>open it live right here</strong>, or grab the file from the source tree under <code>apps/</code> and open it locally (Chrome for the voice features). No build step, no server, no network dependency of its own. Where an AI concierge is offered you bring your own Claude key; every app carries an honest privacy panel. For exactly what leaves your machine — the Anthropic key path, the browser-speech-to-Google exception, and Vedetta's market-data providers — see <a href="products.html#ai-h">AI interactions · bring your own key</a>.</p>
    </div>
    <div class="tablewrap">
      <table>
        <thead><tr><th>App</th><th>Open</th><th>What it is</th></tr></thead>
        <tbody>
          <tr><td><strong>Sotto</strong></td><td><a href="/apps/sotto/">Open&nbsp;→</a></td><td>Privacy-first voice assistant</td></tr>
          <tr><td><strong>Vedetta</strong></td><td><a href="/apps/vedetta/">Open&nbsp;→</a></td><td>Voice markets lookout — holdings never leave the device</td></tr>
          <tr><td><strong>Tolmach</strong></td><td><a href="/apps/tolmach/">Open&nbsp;→</a></td><td>Private interpreter + meeting minutes</td></tr>
          <tr><td><strong>Postern Store</strong></td><td><a href="/apps/store/">Open&nbsp;→</a></td><td>Say what you need; it parameterizes the search</td></tr>
          <tr><td><strong>Chiave</strong></td><td><a href="/apps/login/">Open&nbsp;→</a></td><td>Sign in with your wallet — no email, no account</td></tr>
          <tr><td><strong>Sarto</strong></td><td><a href="/apps/onboard/">Open&nbsp;→</a></td><td>Onboarding configurator + transparent controls</td></tr>
          <tr><td><strong>Consiglio</strong></td><td><a href="/apps/enterprise/">Open&nbsp;→</a></td><td>Enterprise admin console</td></tr>
          <tr><td><strong>Gramota</strong></td><td><a href="/apps/gramota/">Open&nbsp;→</a></td><td>Enterprise license onboarding — tier → DUNS → signed license</td></tr>
          <tr><td><strong>Gramota&nbsp;KYC</strong></td><td><a href="/apps/gramota-kyc/">Open&nbsp;→</a></td><td>On-device KYC — binds an owner to a company, PII-free verdict</td></tr>
          <tr><td><strong>NoporIS&nbsp;Gate</strong></td><td><a href="/apps/noporis-gate/">Open&nbsp;→</a></td><td>Deny-by-default consent levers between two personas (reference)</td></tr>
          <tr><td><strong>NoporIS&nbsp;Switcher</strong></td><td><a href="/apps/noporis-switcher/">Open&nbsp;→</a></td><td>The guarded persona bridge — a managed-profile persona switch (reference)</td></tr>
          <tr><td><strong>Sloboda&nbsp;Gate</strong></td><td><a href="/apps/sloboda-gate/">Open&nbsp;→</a></td><td>Deny-by-default lever store for the Android compat tier (reference)</td></tr>
          <tr><td><strong>Izbushka</strong></td><td><a href="/apps/izbushka/">Open&nbsp;→</a></td><td>Task portal — the door into Yagabona; authors signed manifests, makes no calls (<code>connect-src 'none'</code>)</td></tr>
          <tr><td><strong>Ezekiel&nbsp;1</strong></td><td><a href="/apps/ezekiel1/">Open&nbsp;→</a></td><td>Access-layer governance console (personal + business) — runs fully offline (<code>connect-src 'none'</code>)</td></tr>
          <tr><td><strong>Postern</strong> <span class="small dim">— full mobile PWA</span></td><td><a href="/apps/postern/">Open&nbsp;→</a></td><td><strong>REAL post-quantum keygen and signing</strong> (ML-DSA-65&nbsp;&#8214;&nbsp;Falcon-1024, in WASM on your device); create a wallet or import a <code>bloch-cli</code> <code>wallet.json</code>; balances read live via the hosted <code>/rpc</code>. <strong>Installable PWA</strong> — open on your phone, add to home screen. Unaudited beta, software keystore (not a Secure Enclave), zero-value testnet.</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</section>

<section aria-labelledby="video-h">
  <div class="wrap">
    <p class="kicker" id="video-h">2 · Demo videos</p>
    <h2>What it looks like — labelled for what it is.</h2>
    <div class="prose">
      <p>Three short videos, each labelled on its own frames. The two <strong>Postern OS</strong> videos are <strong>UI design previews — concept walkthroughs, not screen recordings of a built image</strong>. Status has moved since they were made: the desktop x86_64 ISO is now <strong>built, hosted, and release-signed, with a QEMU boot still pending (no boot log published yet)</strong>, and its UI is hardened GNOME, not the concept shown; the <strong>mobile image is now built, hosted, and release-signed, but has not been boot-tested on any platform</strong> (so this remains a design preview, not a recording of a running phone). The real, signed x86_64 ISOs are in <a href="#os-h">section 3 below</a> with checksums and a signature — a QEMU boot is not a hardware boot, and we won't fake an installer for anything we haven't hosted. The <strong>Sarto</strong> video is a walkthrough of the onboarding web app you can open today from <code>apps/postern-onboard/index.html</code>. Nothing shown here is finished, audited, or a security claim.</p>
    </div>
    <div class="videos">
      <figure>
        <video controls muted playsinline preload="metadata">
          <source src="/media/postern-os-mobile-v2.mp4" type="video/mp4">
        </video>
        <figcaption class="small"><strong>Postern OS · mobile — UI design preview.</strong> A concept walkthrough of the mobile interface. This is the design, not a recording of a running OS: the mobile image is now <strong>built, hosted, and release-signed, but not yet boot-tested on any platform</strong>.</figcaption>
      </figure>
      <figure>
        <video controls muted playsinline preload="metadata">
          <source src="/media/postern-os-desktop-v2.mp4" type="video/mp4">
        </video>
        <figcaption class="small"><strong>Postern OS · desktop — UI design preview.</strong> A concept walkthrough of the desktop interface. This is the design, not a recording of a built OS. <strong>Update: the desktop x86_64 ISO is now built, hosted, and release-signed — a QEMU boot is still pending (no boot log published yet) and a hardware boot is further out — and its real UI is hardened GNOME, not this concept. Download it in <a href="#os-h">section 3</a>.</strong></figcaption>
      </figure>
      <figure>
        <video controls muted playsinline preload="metadata">
          <source src="/media/postern-sarto-tutorial.mp4" type="video/mp4">
        </video>
        <figcaption class="small"><strong>Sarto — onboarding tutorial.</strong> A walkthrough of the Sarto web app: configuring Postern and connecting the AI concierge with <strong>your own Claude API key</strong> (bring-your-own-key; no key of ours, no account). Sarto is beta and unaudited, like everything here.</figcaption>
      </figure>
    </div>
  </div>
</section>

<section aria-labelledby="os-h">
  <div class="wrap">
    <p class="kicker" id="os-h">3 · The reproducible OS</p>
    <h2>Postern OS — download, verify, then boot.</h2>
    <div class="prose">
      <p>The <code>os/</code> directory holds declarative NixOS profiles: a minimal image that boots into a running node as a hardened systemd service (dedicated user, <code>ProtectSystem=strict</code>, syscall filtering), plus desktop, mobile, browser, cloud, and attestation profiles. Because it's Nix, <strong>the same inputs produce the same image</strong> — that reproducibility is the product.</p>
      <p><strong>Honest status:</strong> the <strong>x86_64 node and desktop ISOs are now hosted, release-signed, and downloadable below</strong>, each with its SHA-256 digest and a minisign signature. A <strong>QEMU boot is still pending for both</strong> — no boot log or <code>.evidence</code> sidecar is published next to either ISO yet, so we make no boot claim — and a <strong>boot on physical hardware is further out</strong>. Hosting and signing a release <strong>is not attestation</strong>; built is not booted; we won't imply otherwise. The <strong>mobile image (aarch64, PinePhone / Mobile NixOS) is now built, hosted, and release-signed and is downloadable below</strong> with its SHA-256 and the same signed checksum list — but it has <strong>not been boot-tested on any platform</strong> (neither QEMU-aarch64 nor hardware), so it is the least-proven artifact here and "built + signed" is emphatically not "it boots." Prefer to build it yourself? That path is still below, and it remains the strongest verification.</p>
    </div>
    <div class="tablewrap">
      <table>
        <thead><tr><th>Artifact</th><th>Size</th><th>Status</th><th>Download</th><th>SHA-256</th></tr></thead>
        <tbody>
          <tr>
            <td><strong>Postern OS — node appliance ISO</strong><br><span class="small dim">x86_64 · UEFI</span></td>
            <td>1.47&nbsp;GB</td>
            <td><span class="badge built">built · hosted + signed · QEMU boot pending</span></td>
            <td><a href="/dl/postern-os-node-x86_64.iso">Download ISO&nbsp;→</a></td>
            <td><code>8f575705fd437314c9f2dd4a873d523890294b36e3fc323df54cbfea026c0f4b</code></td>
          </tr>
          <tr>
            <td><strong>Postern OS — desktop ISO</strong><br><span class="small dim">x86_64 · UEFI</span></td>
            <td>2.66&nbsp;GB</td>
            <td><span class="badge built">built · hosted + signed · QEMU boot pending</span></td>
            <td><a href="/dl/postern-os-desktop-x86_64.iso">Download ISO&nbsp;→</a></td>
            <td><code>e6344619c50f283030388fb2083655ce69140315b7879cb58744cae37d999c16</code></td>
          </tr>
          <tr>
            <td><strong>Postern OS — mobile image</strong><br><span class="small dim">aarch64 · PinePhone (Mobile NixOS)</span></td>
            <td>1.31&nbsp;GB</td>
            <td><span class="badge proto">built · hosted + signed · not yet boot-tested (QEMU or hardware)</span></td>
            <td><a href="/dl/postern-os-mobile-pinephone-aarch64.img">Download .img&nbsp;→</a></td>
            <td><code>708aeffc48142db003a1f8ce1305ec2fdf3422090800f47ef1513fcaf0271639</code></td>
          </tr>
        </tbody>
      </table>
    </div>
    <p class="prose small">Signed checksum list: <a href="${OS_BASE}/os/v0.1/SHA256SUMS">SHA256SUMS</a> · signature: <a href="${OS_BASE}/os/v0.1/SHA256SUMS.minisig">SHA256SUMS.minisig</a> · minisign public key: <a href="${OS_BASE}/os/keys/postern-os-minisign.pub">postern-os-minisign.pub</a>.</p>

    <div class="warnpanel" role="note">
      <h3>Verify before you boot — both steps, every time</h3>
      <p>A download you haven't verified is a download you're trusting to the network. Fetch the <a href="${OS_BASE}/os/v0.1/SHA256SUMS">SHA256SUMS</a> list and its <a href="${OS_BASE}/os/v0.1/SHA256SUMS.minisig">minisign signature</a> into the same folder as the ISOs, then run both checks — neither is optional:</p>
<pre><code># 1. Checksum — every ISO you downloaded must verify against the signed list
sha256sum -c SHA256SUMS

# 2. Signature — proves the checksum list itself was published by Postern.
#    The key is inline below; or fetch it:
#    ${OS_BASE}/os/keys/postern-os-minisign.pub
minisign -Vm SHA256SUMS -P ${OS_MINISIGN_KEY}</code></pre>
      <p>The checksum proves the file is intact; the signature proves the checksum list came from us. You need both. The minisign public key <code>${OS_MINISIGN_KEY}</code> is published here, <a href="${OS_BASE}/os/keys/postern-os-minisign.pub">as a file</a>, and in the release notes, so you can cross-check it from more than one independent place.</p>
    </div>

    <div class="warnpanel" role="note">
      <h3>Before you install — read these</h3>
      <ul>
        <li><strong>Back up first. The installer repartitions the target disk</strong> and everything on it is gone. There is no undo.</li>
        <li><strong>Full-disk encryption (LUKS) means your passphrase is the data.</strong> Lose it and nobody — including us, by design — can recover the disk. Store it somewhere that isn't the same machine.</li>
        <li><strong>Secure Boot: these images are not signed for Microsoft-endorsed Secure Boot yet.</strong> Disable Secure Boot in firmware, or enroll your own keys — both change your machine's security posture. Signed-shim support is planned, not shipped.</li>
        <li><strong>No boot has been observed yet.</strong> Neither ISO has a published QEMU boot log, and neither has booted on physical hardware. Treat both a QEMU boot and a real-hardware install as unproven until the boot evidence is published.</li>
        <li><strong>The mobile .img is the least-proven artifact — it has not booted anywhere.</strong> It is built, hosted, and release-signed, but it has never been booted on QEMU-aarch64 or on a PinePhone. Flashing it to a device is genuinely experimental; the first hardware boot has not happened. Verify the signature, but don't expect it to come up yet.</li>
        <li><strong>Mainnet beta, unaudited — not a security claim.</strong> Hosting a signed image is not attestation. Evaluate it and reproduce our builds; don't protect real secrets with it yet.</li>
      </ul>
    </div>

    <div class="videos" style="margin:1.6rem 0">
      <figure>
        <video controls muted playsinline preload="metadata">
          <source src="/media/postern-os-install-v2.mp4" type="video/mp4">
        </video>
        <figcaption class="small"><strong>How to build &amp; install Postern OS — desktop + mobile (walkthrough).</strong> Shows the build-from-source process (<code>nix build .#iso</code> / <code>.#mobile-image</code>), flashing, and booting on a compatible device. Since this video was made: the <strong>x86_64 node and desktop ISOs are now hosted and release-signed (download them above)</strong> with a <strong>QEMU boot still pending (no boot log published yet)</strong>; a <strong>physical-hardware boot is further out</strong> (first targets: a PinePhone + a PC); the <strong>mobile image is now built, hosted, and release-signed but not yet boot-tested on any platform</strong>, so the flashing/booting portion of this walkthrough remains the plan, not a demonstrated process. Mainnet-beta, unaudited; not a security claim. Mobile targets only the listed Mobile-NixOS devices — <strong>not any Android</strong>.</figcaption>
      </figure>
    </div>
    <div class="prose">
      <p><strong>Prefer to build it yourself?</strong> That is still the strongest verification — the same inputs produce the same image, which is the whole point:</p>
    </div>
<pre><code># On a Linux host with Nix + flakes, from the source tree:

# Bootable node ISO  ->  ./result/iso/*.iso
nix build .#iso

# Desktop ISO  ->  ./result/iso/*.iso
nix build .#desktop-iso

# Just the node package
nix build .#bloch &amp;&amp; ./result/bin/bloch --help

# Try it in a VM without flashing anything
nixos-rebuild build-vm --flake .#bloch-os &amp;&amp; ./result/bin/run-*-vm</code></pre>
    <p class="prose small">The mobile edition is <strong>built, hosted, and release-signed, but not yet boot-tested on any platform</strong>. See the honest labels on the <a href="products.html">products page</a>.</p>
  </div>
</section>

<section aria-labelledby="pmos-h">
  <div class="wrap">
    <p class="kicker" id="pmos-h">3b · The non-attestable tier</p>
    <h2>Postern for postmarketOS — community edition. The apk repo is now published.</h2>
    <div class="prose">
      <p>A separate, deliberately humbler product: the Postern suite packaged as ordinary postmarketOS/Alpine <strong>apk</strong> packages for phones postmarketOS already supports. It is <strong>not “Postern OS”</strong> and never will be called that: Alpine packages are <strong>not reproducible and not attestable</strong> — our apk signature proves <em>who published it</em>, not <em>what it was built from</em> — and wallet keys on this platform are <strong>software-backed, not hardware-backed</strong>. The attestable images are the Nix-built “Postern OS” family above, only.</p>
      <p><strong>Honest status: three packages are now built, signed, and published for aarch64</strong>, in one signed Alpine apk repository on our public R2 bucket (one signing key for all three): <code>postern-wallet</code> (the real light-wallet CLI), <code>postern-apps</code> (the web-app bundle), and <code>postern</code> (a meta that pulls the two and declares the pmOS runtime deps — phosh + tor — which only resolve on a booted pmOS). Built natively on an aarch64 host (no qemu, no cross) in an Alpine container with <code>abuild</code>, from source tarballs pinned to the <code>v0.1.0-alpha1</code> tags.</p>
      <p><strong>What that is <em>not</em>, spelled out:</strong> it is <strong>three apks and an index — not an operating system</strong>; the flavor / bootable image is <strong>not built</strong>. It is signed with an <strong>alpha build key</strong> (<code>${APK_KEY}</code>), not a stable, long-lived Postern release key — treat the signature as “this build, this key,” not a trust anchor. It has <strong>never been booted or run on a physical device</strong> — “built + signed + installs via apk” is not “runs correctly on your phone.” Non-attestable (Alpine/musl, not Nix), <strong>unaudited</strong>, and the coin the wallet holds is <strong>worthless by design</strong>.</p>
    </div>

    <h3 style="margin-top:1.6rem">Which phones can it reach?</h3>
    <div class="prose">
      <p>Because these are plain <strong>aarch64 apk packages</strong>, they add onto <strong>any 64-bit postmarketOS install</strong> — and postmarketOS itself now reaches on the order of <strong>~700 device models</strong>. But <em>reachable</em> is postmarketOS's word, not ours: <strong>we have booted Postern on none of them.</strong> "the apks install" is not "it runs on your phone."</p>
      <p>postmarketOS sorts devices by how complete their support is. Since the v24.12 release the top <em>main</em> tier is essentially QEMU-only; the real, actively-maintained phones live in <strong>community</strong>, and the long tail (<strong>254 devices</strong> in the v26.06 release the apks target) sits in <strong>testing</strong>, where core hardware — modem, camera, GPU — may simply not work yet. <strong>postmarketOS's own device pages at <span class="mono">wiki.postmarketos.org</span> are the source of truth</strong> for what each one can and can't do; check yours before you expect anything.</p>
    </div>
    <p class="prose small" style="margin-top:.6rem">Better-supported <strong>community-tier, aarch64</strong> phones — the realistic targets (this is <strong>postmarketOS</strong>'s support, <strong>not</strong> Postern-tested):</p>
    <div class="tablewrap">
      <table>
        <thead><tr><th>Device</th><th>postmarketOS codename</th></tr></thead>
        <tbody>
          <tr><td><strong>PINE64 PinePhone</strong></td><td><code>pine64-pinephone</code></td></tr>
          <tr><td><strong>PINE64 PinePhone Pro</strong></td><td><code>pine64-pinephonepro</code></td></tr>
          <tr><td><strong>PINE64 PineTab 2</strong></td><td><code>pine64-pinetab2</code></td></tr>
          <tr><td><strong>Purism Librem 5</strong></td><td><code>purism-librem5</code></td></tr>
          <tr><td><strong>OnePlus 6 / 6T</strong></td><td><code>oneplus-enchilada</code> / <code>oneplus-fajita</code></td></tr>
          <tr><td><strong>Google Pixel 3a / 3a XL</strong></td><td><code>google-sargo</code> / <code>google-bonito</code></td></tr>
          <tr><td><strong>Xiaomi Poco F1</strong></td><td><code>xiaomi-beryllium</code></td></tr>
          <tr><td><strong>Fairphone 4 / 5</strong></td><td><code>fairphone-fp4</code> / <code>fairphone-fp5</code></td></tr>
          <tr><td><strong>SHIFT SHIFT6mq</strong></td><td><code>shift-axolotl</code></td></tr>
        </tbody>
      </table>
    </div>
    <p class="prose small">Only the <strong>PinePhone</strong> is also the Mobile-NixOS <em>"Postern OS"</em> image target in section 3a — and even that image has <strong>not booted anywhere yet</strong>. Every row here is a place the apks <em>can be added</em>, not a device we have run. <strong>32-bit (armv7) phones are out of scope</strong> — these packages are aarch64 only. The list is a moving target; postmarketOS's device wiki, not this page, is authoritative.</p>

    <p class="prose small">Add it on a pmOS / Alpine aarch64 device:</p>
    <pre><code>wget -O /etc/apk/keys/${APK_KEY}.rsa.pub \\
  ${OS_BASE}/pmos/keys/${APK_KEY}.rsa.pub
echo "${REPO_BASE}" &gt;&gt; /etc/apk/repositories
apk update
apk add postern-wallet      # just the wallet CLI, or:
apk add postern             # the meta (wallet + apps + phosh + tor) — on a real pmOS</code></pre>
    <p class="prose small">Signing key: <code>${APK_KEY}</code> — an alpha build key. A stable release key with a documented rotation, published in at least two places, is a prerequisite before this repo is recommended broadly. When the flavor image is built and a device has actually booted it, that milestone will appear here with the same zero-count honesty.</p>
    <figure style="margin:1.6rem 0">
      <video controls muted playsinline preload="metadata" src="/media/postern-for-postmarketos-walkthrough.mp4"></video>
      <figcaption class="small"><strong>Postern for postmarketOS — walkthrough.</strong> A screen recording of the real web apps, the wallet CLI, and the <code>apk add</code> install captured on screen — two of the apps running live against a user's own Anthropic key. It is <strong>not</strong> a recording of a booted device: nothing here has run on phone hardware.</figcaption>
    </figure>
    <div class="warnpanel" role="note">
      <h3>Signed is not attestable</h3>
      <ul>
        <li>The apk signature proves <strong>who published it</strong>, not <strong>what it was built from</strong>. No reproducibility, no attestation claim.</li>
        <li>Wallet keys on this tier are <strong>software-backed, not hardware-backed</strong> — a software keystore.</li>
        <li>The attestable path is the Nix-built <strong>“Postern OS”</strong> family above, only.</li>
        <li>Mainnet beta, <strong>unaudited</strong>; the coin carries <strong>no value claim</strong>.</li>
      </ul>
    </div>
  </div>
</section>

<section aria-labelledby="desk-h">
  <div class="wrap">
    <p class="kicker" id="desk-h">4 · The desktop app</p>
    <h2>Postern Desktop — Tauri, build from source.</h2>
    <div class="prose">
      <p>A desktop app for the OS you already run (Linux first; cross-platform): start/stop and monitor a node, hold a wallet (mnemonic shown once, byte-identical addresses to the mobile core), watch the miner, stream the logs. Rust backend, dependency-free web UI.</p>
      <p><strong>Postern Desktop includes an Encrypted Backup pane and a Swap pane</strong> — both <strong>reference prototypes, unaudited</strong>:</p>
      <ul>
        <li><strong>Encrypted Backup → Filecoin.</strong> The pane seals a file <strong>locally</strong> with the Postern AEAD seal (XChaCha20-Poly1305), writes a <strong>post-quantum SHAKE-256 “DATA0” integrity anchor</strong>, then performs a <strong>real upload of the sealed ciphertext to Filecoin</strong> through a Lighthouse S3 token — a real content ID (CID) comes back. <strong>Only sealed ciphertext ever leaves the device</strong>; keys and plaintext do not. It spools through a <strong>durable, crash-safe on-disk backup queue</strong> (the <code>DirBackend</code> spool). A <strong>reference prototype, unaudited</strong> — don't entrust a real backup to it yet.</li>
      </ul>
      <p>It builds from source in <code>desktop/</code> with the standard Rust + Tauri toolchain (<code>cargo tauri build</code> after the Tauri prerequisites for your platform). The desktop command surface is hardened — a <strong>sidecar sha256 integrity-pin (fail-closed)</strong>, default-deny capabilities, a strict CSP — but that is a pin, not an audit, and everything here is a beta.</p>
      <div style="margin:1.4rem 0 0;border:1px solid var(--border);border-radius:10px;padding:1rem 1.2rem;background:rgba(180,140,60,.06)">
        <p style="margin:0 0 .4rem"><strong>Download — Postern Desktop 0.1.0 · public beta (macOS)</strong> &nbsp;<span class="small dim">unaudited reference build</span></p>
        <p class="small dim" style="margin:0 0 .7rem">Building from source (above) is the primary, fully-verifiable path. This <code>.dmg</code> is a convenience build for <strong>testing only</strong> — <strong>unaudited, not production</strong>; don't entrust anything real to it yet.</p>
        <p style="margin:0 0 .7rem"><a class="btn primary" href="/dl/Postern-Desktop-macOS.dmg" download>Download the .dmg (macOS · ~11&nbsp;MB) →</a></p>
        <ul class="small dim" style="margin:.2rem 0 0">
          <li><strong>Verify before opening.</strong> SHA-256 <code>09382424f009c27fc102f2993a2afd8981acc28f7bfe95a3dd4ec6af0d46128c</code> — run <code>shasum -a 256 Postern-Desktop-macOS.dmg</code> and compare. <strong>This replaces the build published earlier on 2026-07-18</strong> (<code>d9166d7a…</code>), which was withdrawn: it came from a partial branch and its Swap pane badged itself &ldquo;live&rdquo;. Discard that one.</li>
          <li><strong>Swap reads &ldquo;preview&rdquo; here, and that is correct.</strong> The constant-product quote math and the EVM calldata are real and tested, but <strong>chain_id 700771 is unregistered, WBLCH was never deployed and no pools exist</strong> — nothing can be signed or broadcast, and the v1 bridge vault is custody.</li>
          <li><strong>Not Apple-notarized.</strong> Ad-hoc signed only. Gatekeeper will warn: <strong>right-click the app → Open</strong> the first time, or run <code>xattr -dr com.apple.quarantine &quot;/Applications/Postern Desktop.app&quot;</code>.</li>
          <li><strong>Intel x86_64 build</strong> — runs on Intel Macs and on Apple Silicon via <strong>Rosetta&nbsp;2</strong>.</li>
        </ul>
      </div>
      <div style="margin:1.4rem 0 0;border:1px solid var(--border);border-radius:10px;padding:1rem 1.2rem;background:rgba(70,120,180,.06)">
        <p style="margin:0 0 .4rem"><strong>Postern — mobile (PWA)</strong> &nbsp;<span class="small dim">the full app, no install store</span></p>
        <p class="small dim" style="margin:0 0 .7rem">The whole Postern app running in your phone's browser: a real post-quantum wallet (ML-DSA-65&nbsp;&#8214;&nbsp;Falcon-1024 keygen and signing in WASM, keys never leave the phone; create one or import a <code>bloch-cli</code> <code>wallet.json</code>), plus node status, vault, encrypted backup and the other panes. Add it to your home screen — iPhone and Android, no store, no signup.</p>
        <p style="margin:0 0 .7rem"><a class="btn primary" href="/apps/postern/">Open Postern →</a></p>
        <ul class="small dim" style="margin:.2rem 0 0">
          <li><strong>Unaudited beta, zero-value testnet.</strong> Your recovery phrase is the only backup — write it on paper before you use it.</li>
          <li>Software keystore in the browser, <strong>not</strong> the phone's Secure Enclave/StrongBox; installing the PWA is not a security upgrade. Panes that need a native host (run-a-node, hardware vault) show a clearly-labelled preview.</li>
        </ul>
      </div>
      <div class="warnpanel" role="note" style="margin:1rem 0 0">
        <h3>Windows installer — still withdrawn</h3>
        <p>The <code>.msi</code> published earlier (<code>f54772ad…</code>) came from the same partial branch and carries the same live-badged Swap pane, so it stays down. It cannot simply be rebuilt alongside the macOS one: <strong>Tauri does not cross-bundle</strong> — <code>.msi</code>/NSIS are only emitted on Windows — and the <code>bloch-desktop-win</code> CI runner is not provisioned yet. Until one exists, <strong>build from source</strong> on Windows (see <code>desktop/BUILD.md</code>). Linux is in the same position.</p>
      </div>
    </div>
    <figure style="margin:1.4rem 0 0">
      <video controls muted playsinline preload="metadata" style="width:100%;max-width:100%;border:1px solid var(--border);border-radius:10px;background:#000">
        <source src="/media/postern-desktop-features-v2.mp4" type="video/mp4">
      </video>
      <figcaption class="small dim" style="margin-top:.6rem"><strong>Postern Desktop — features walkthrough</strong>, including the real Encrypted Backup and Swap panes. A demo of the app you build from source; unaudited reference prototype, not a security claim.</figcaption>
    </figure>
    <figure style="margin:1.4rem 0 0">
      <video controls muted playsinline preload="metadata" style="width:100%;max-width:100%;border:1px solid var(--border);border-radius:10px;background:#000">
        <source src="/media/postern-encrypted-backup-filecoin.mp4" type="video/mp4">
      </video>
      <figcaption class="small dim" style="margin-top:.6rem"><strong>Encrypted Backup → Filecoin — tutorial.</strong> Sealing a file locally, anchoring a SHAKE-256 DATA0 integrity commitment, then uploading the sealed ciphertext to Filecoin (real CID returned). Only ciphertext leaves the device. Reference prototype, unaudited.</figcaption>
    </figure>
  </div>
</section>

<section aria-labelledby="src-h">
  <div class="wrap">
    <p class="kicker" id="src-h">5 · The source itself</p>
    <h2>Where the code lives.</h2>
    <div class="prose">
      <p>The <strong>product suite</strong> (crates, apps, OS profiles, desktop, mobile) is the Postern Labs source tree — MIT / Apache-2.0 per crate. <code>cargo build --workspace</code> builds the product cores; the crates that need protocol crypto pull it as a pinned git dependency.</p>
      <p>The <strong>protocol</strong> is not ours to host: Bloch-SIS-PoW lives in its own ownerless repository at <code>gitlab.com/blochsispow-group/BlochSISPoW-project</code> — rendered as text, not a link, because this site makes no external requests and the protocol has no official site. See <a href="postern-vs-bloch.html">Postern &amp; Bloch — two different things</a>.</p>
    </div>
    <div class="warnpanel" role="note">
      <h3>Before you run anything</h3>
      <p>All of it is <strong>beta and unaudited</strong>. Evaluate it, break it, reproduce our builds, file findings — but <strong>do not put real secrets in the vault, real files through the courier, or treat the chain's coins as a store of value</strong>. The chain is a <strong>mainnet beta</strong>: unaudited, 51%-attackable, running the <strong>difficulty-driven k-ramp</strong> (k=4 today, rising with hashrate — a structural filter, not a security claim) — and its coins carry <strong>no value claim</strong>. Not a security, not an asset; use at your own risk.</p>
    </div>
  </div>
</section>
`;

/* ============================================================
   PAGE: Run a node
   ============================================================ */

const MIGRATION = `
<section class="hero">
  <div class="wrap">
    <div class="rule" aria-hidden="true"></div>
    <p class="kicker">Network status &middot; 19 July 2026</p>
    <h1>Why Bloch is migrating to SHA-256.</h1>
    <p class="lede">A new node <strong>cannot sync from genesis</strong>: roughly <strong>95% of block bodies no longer exist on any node</strong> and cannot be recovered. Joining the network today therefore requires the <a href="snapshot.html">published snapshot</a> — that path works and is the supported one. What the migration fixes is the underlying position: a chain that can only be joined by trusting a downloaded database, and cannot replay its own history. This page explains what broke, what is safe, and what happens next. Nothing here is launched.</p>
  </div>
</section>

<section class="band">
  <div class="wrap prose">
    <h2>What broke</h2>
    <p>Nodes prune block bodies below <code>tip &minus; 10,000</code>. Pruning deletes the bodies but keeps the header/DAG map — so a pruned node keeps <strong>advertising headers for blocks whose bodies it deleted</strong>.</p>
    <p>A fresh node that tries to sync <strong>from genesis</strong> therefore connects, asks for the chain from block 0, is served 500 valid headers, requests the bodies, and receives nothing. It waits, re-asks 30 seconds later, and loops. Measured on a clean machine: <strong>4,397 identical rounds, still at height 1, with 15 peers connected</strong>.</p>
    <p>This is why <a href="snapshot.html">snapshot bootstrap</a> exists and is the supported path: you download a database that already contains the surviving history, and sync forward from there. It works. But it is worth being clear about what it means — <strong>every new participant begins by trusting a file</strong>, because the network can no longer prove its own past to them.</p>
    <div class="tablewrap">
      <table>
        <thead><tr><th>Height</th><th>Hash resolves</th><th>Body present</th></tr></thead>
        <tbody>
          <tr><td>1</td><td>yes</td><td><strong>no</strong></td></tr>
          <tr><td>500</td><td>yes</td><td><strong>no</strong></td></tr>
          <tr><td>402,000</td><td>yes</td><td><strong>no</strong></td></tr>
          <tr><td>402,567</td><td>yes</td><td>yes</td></tr>
          <tr><td>410,000</td><td>yes</td><td>yes</td></tr>
        </tbody>
      </table>
    </div>
    <p class="small dim">Probed directly on the canonical node. The cliff sits exactly at its <code>pruned_height</code>. Fleet-wide the lowest is ~394,913, and no backup of the earlier bodies exists anywhere.</p>
    <p>A second defect hid it: a node that could not serve a body <strong>dropped the request silently</strong> and logged at <code>debug</code> level. The requester could not tell a pruned body from a lost packet, so it waited forever — and at the default log level the fault was invisible.</p>
  </div>
</section>

<section class="band alt">
  <div class="wrap prose">
    <h2>What is safe</h2>
    <p>Pruning deletes block bodies. It <strong>does not touch the UTXO set</strong>. Every coin mined so far is intact and was never at risk.</p>
    <p>A full snapshot was taken from the canonical node, read-only, while it kept mining:</p>
    <pre><code>UTXOs        : 413,743
total supply : 3,475,441,200 BLCH
SHAKE-256    : d3de5e51ee9dbbf36ed79981cbf66eb50a8894fc034610a20a5ee01eb9060637</code></pre>
    <p>It passes an independent arithmetic check: <strong>3,475,441,200 &divide; 8,400 = 413,743 exactly</strong> — one coinbase per block, no fragmentation. The root proves the file is intact; the division proves the set is complete. A snapshot missing a single UTXO passes the first and fails the second.</p>
    <p><strong>This snapshot is not the migration artifact.</strong> It was taken live, so it corresponds to no frozen height, and our own tool refuses to emit genesis constants from it for exactly that reason. The real one will be taken with the node stopped at an <strong>announced height</strong>, with height and root published together so anyone can reproduce it.</p>
  </div>
</section>

<section class="band">
  <div class="wrap prose">
    <h2>What the migration is</h2>
    <p>A <strong>new chain</strong> whose genesis commits to that snapshot — not a fork of the old one. The old chain cannot serve its own history, so replaying it from genesis is not something anyone can do, ever. A newcomer would start from a distributed artifact either way; this makes that artifact explicit and hash-bound.</p>
    <ul>
      <li><strong>Proof-of-work becomes double SHA-256</strong> with an 80-byte mining header, ported from a sibling codebase that already runs it. This is what makes existing ASIC and rented hashrate able to mine it at all.</li>
      <li><strong>Balances carry over</strong>, bound to the published commitment. A node that loads a snapshot which does not hash to the committed root must refuse to start.</li>
      <li><strong>Signatures do not change.</strong> ML-DSA-65 &#8214; Falcon-1024 stay exactly as they are.</li>
    </ul>
    <h3>On post-quantum security</h3>
    <p>Changing the proof-of-work does <strong>not</strong> weaken post-quantum protection of anyone's coins, and it is worth being precise about why. Shor's algorithm breaks signatures — that is the catastrophic quantum threat, and it is why this chain signs with ML-DSA-65 and Falcon-1024. Against a hash function there is only Grover, which halves the effective strength: SHA-256 retains ~128 bits against a quantum adversary, which is comfortable.</p>
    <p>Post-quantum safety here lives in the signature scheme and the address format, and both are untouched. What is set aside is a research claim about post-quantum <em>mining</em> — not the security of any coin.</p>
  </div>
</section>

<section class="band alt">
  <div class="wrap prose">
    <h2>The risk we are not hiding</h2>
    <div class="warnpanel" role="note">
      <h3>A small SHA-256 chain is cheap to attack</h3>
      <p>SHA-256 hashrate is rented on a liquid market. The same property that lets miners join immediately lets anyone rent enough hashrate to reorganise a young chain for the price of a few hours' rental — this is the ordinary cause of death for small SHA-256 chains, not a hypothetical.</p>
      <p>Today's chain is broken but <em>not</em> exposed this way, because no rental market exists for its lattice proof-of-work. Migrating trades a growth problem for a security problem, and that trade has to be covered rather than wished away.</p>
    </div>
    <p>The intended answer is <strong>FFG finality</strong> — a 14-of-21 ML-DSA-65 committee that finalises checkpoints, making deep reorganisation impossible regardless of rented hashrate.</p>
    <p><strong>FFG is not ready.</strong> The crate exists; it is not integrated into the node. Activating finality that has no committee finalises nothing. So it lands in two stages, and the gap between them is deliberate:</p>
    <div class="tablewrap">
      <table>
        <thead><tr><th>Milestone</th><th>Height</th><th>What happens</th></tr></thead>
        <tbody>
          <tr><td>Genesis</td><td>0</td><td>SHA-256 live; FFG compiled and <strong>off</strong></td></tr>
          <tr><td>Committee formation</td><td>250,000</td><td>21 seats filled, votes cast and <strong>ignored by consensus</strong></td></tr>
          <tr><td><strong>FFG activation</strong></td><td><strong>500,000</strong></td><td>14-of-21 quorum begins finalising</td></tr>
        </tbody>
      </table>
    </div>
    <p>The interval between the last two is the point: the committee runs in the open, producing real votes that cannot yet break anything, so failures surface before they matter. If something is wrong, activation slips — no fork required, because the votes carry no weight until it.</p>
    <p>Between genesis and activation the chain is exposed, and that window will be covered explicitly. How it is covered has not been decided; when it is, it will be stated plainly here, including what it costs in decentralisation while it lasts.</p>
  </div>
</section>

<section class="band">
  <div class="wrap prose">
    <h2>Status, honestly</h2>
    <p><strong>Nothing is launched.</strong> The snapshot tool, the commitment generator and the archival-node flag are written and tested. The SHA-256 chain itself is being built and will be proven end-to-end on a throwaway machine — carrying the real balances, verified against the real numbers — before anyone is asked to trust it.</p>
    <p>One node is currently producing blocks, and new nodes join by downloading a snapshot rather than by verifying the chain. That is a fragile position and it is not being presented as anything else.</p>
    <p class="small dim">BLCH is worthless by design and is not a security; running a node is participation in an ownerless commons, not an investment. This is unaudited, pre-1.0 reference software.</p>
  </div>
</section>
`;

const RUN_A_NODE = `
<section class="hero">
  <div class="wrap">
    <div class="rule" aria-hidden="true"></div>
    <p class="kicker">Run a mainnet-beta node</p>
    <h1>Join the Bloch-SIS-PoW mainnet beta.</h1>
    <p class="lede">This page walks you through building and running a node of the <strong>ownerless</strong> Bloch-SIS-PoW protocol on its <strong>mainnet beta</strong> — as a relay, or as a solo miner. The network is nascent and unaudited, and its coins carry <strong>no value claim</strong>. You are helping run and harden experimental post-quantum PoW research, nothing more.</p>
    <div class="warnpanel" role="note">
      <h3>Read before running anything</h3>
      <ul>
        <li><strong>Mainnet beta — a designation, not a security claim.</strong> As of node v0.1.0-alpha2 the Module-SIS gate is a <strong>difficulty-driven k-ramp</strong>: <strong>k=4 today</strong>, rising 5→6→7→8 as the network's own ASERT difficulty sustains above spaced thresholds, and easing back if hashrate falls — the Bitcoin model. This replaces the fixed k=8 gate, which was choking block production at low hashrate for <strong>no security gain</strong> (β=q/16 is the trivial regime at any k — raising k adds no cryptographic hardness). The ramp is a structural filter, <strong>not a security claim</strong>; real security is <strong>cumulative SHAKE-256 hashcash work — hashrate × time</strong>. Onboarding: a new node can <strong>sync from genesis</strong> (the historical chain validates under the ramp) or fast-sync from the optional <strong>signed snapshot</strong>.</li>
        <li><strong>Very few nodes, low hashrate → 51%-attackable.</strong> The software is <strong>unaudited</strong>: a third-party audit is contracted but <strong>not done yet</strong>, and the concrete-security analysis and IACR ePrint are still outstanding.</li>
        <li><strong>Recently patched.</strong> An <strong>internal</strong> security review's fixes are merged into <code>main</code> and deployed to the public demo nodes — a fresh build from this page already includes them (this is separate from, and does not substitute for, the outstanding third-party audit). Already running an older build? <a href="security.html">Update guide &amp; disclosures →</a></li>
        <li><strong>The coin is not a security and not an asset.</strong> No token sale, no listing effort, no market-making, no price — <strong>no value claim</strong>. Disclosed in full: a 17% founder premine (10-year cliff, 40-year vest), structurally passive. <a href="disclaimer.html">Full disclaimer</a>.</li>
        <li>Run it to evaluate, strengthen, break, and report — <strong>not</strong> as an investment. Use at your own risk.</li>
      </ul>
    </div>
  </div>
</section>

<section aria-labelledby="setupvid-h">
  <div class="wrap">
    <p class="kicker" id="setupvid-h">Watch first · snapshot sync</p>
    <h2>The whole setup, in one short video.</h2>
    <figure style="margin:1.2rem 0 0">
      <video controls playsinline preload="metadata" poster="/media/bloch-node-setup-v3-poster.png" style="width:100%;max-width:100%;border:1px solid var(--border);border-radius:10px;background:#000">
        <source src="/media/bloch-node-setup-v3.mp4" type="video/mp4">
        <track kind="subtitles" srclang="en" label="English" default src="/media/bloch-node-setup-v3.vtt">
      </video>
      <figcaption class="small dim" style="margin-top:.6rem"><strong>Snapshot sync — set up a Bloch node in ~3 min</strong> · narrated · English captions. The video is an overview — the <strong>written steps below are authoritative</strong>. See also <a href="snapshot.html">Snapshot sync — why &amp; how</a>.</figcaption>
    </figure>
  </div>
</section>

<section aria-labelledby="src-h">
  <div class="wrap">
    <p class="kicker" id="src-h">Step 1 · Get the source</p>
    <h2>Clone the protocol repository.</h2>
    <div class="prose">
      <p>The protocol is not a Postern Labs product and has no official website. It lives in its own ownerless repository — rendered as text on purpose, because the protocol has no official site to link to and this site will not invent one:</p>
    </div>
<pre><code>gitlab.com/blochsispow-group/BlochSISPoW-project</code></pre>
<pre><code># Prefix the path above with your git host scheme of choice, then:
git clone &lt;the repository above&gt; bloch
cd bloch</code></pre>
    <p class="prose small">Prerequisites: a Rust toolchain (rustup, stable), plus a C toolchain — <code>clang</code>, <code>cmake</code>, <code>pkg-config</code> — needed by RocksDB, blst, and the PQClean-based crypto crates.</p>
  </div>
</section>

<section aria-labelledby="build-h">
  <div class="wrap">
    <p class="kicker" id="build-h">Step 2 · Build</p>
    <h2>One command, one binary (plus friends).</h2>
<pre><code>cargo build --release</code></pre>
    <div class="prose">
      <p>Binaries land in <code>target/release/</code>: <code>bloch</code> (the full node), <code>bloch-cli</code> (an RPC client, like <code>bitcoin-cli</code>), and <code>bloch-wallet</code>. Verify the build with <code>cargo test</code> if you like — the suite should pass.</p>
      <p>Prefer an appliance? The Postern OS node ISO (x86_64) is now <strong>hosted, release-signed, and QEMU-boots on x86_64</strong> (a first hardware boot is still further out) — grab it, with its checksum and signature, from <a href="downloads.html">downloads</a>. Building from source, as on this page, remains the strongest verification.</p>
    </div>
  </div>
</section>

<section aria-labelledby="snap-h">
  <div class="wrap">
    <p class="kicker" id="snap-h">Step 2b · Fast-sync from a snapshot — optional</p>
    <h2>Optional: bootstrap at the tip instead of syncing from genesis.</h2>
    <div class="prose">
      <p>Under the difficulty-driven k-ramp (node v0.1.0-alpha2), a fresh node <strong>can sync from genesis again</strong> — the historical chain validates under the ramp's k=4. If you'd rather skip the initial block download, a <strong>signed snapshot</strong> of a current node's chain state (the pruned RocksDB at the tip) gets you to the tip in one pass. A convenience, not a requirement.</p>
    </div>
<div class="warnpanel" role="note" style="margin:0 0 1rem">
      <h3>The older snapshot is a dead end — use the one below</h3>
      <p>The previously published <code>bloch-db-snapshot.tar.gz</code> ends at height <strong>394,361</strong>. Peers have since pruned block bodies below <strong>~394,913</strong>, so a node restored from it asks for the ~550 blocks in between, <strong>no peer has them, and it stalls forever</strong> with a healthy-looking log. This snapshot (height <strong>408,482</strong>) starts above that gap and syncs normally.</p>
      <p class="small dim">Why this happens: pruning deletes block bodies below <code>tip &minus; 10,000</code>. A published snapshot must be refreshed <strong>before</strong> the network prunes past the height it ends at, or the chain from snapshot to tip breaks silently. That is a real failure this network hit, not a hypothetical.</p>
    </div>
    <pre><code># 1) download the signed snapshot + checksums, verify, restore, then start
curl -O ${OS_BASE}/bloch-db-snapshot-408482.tar.gz
curl -O ${OS_BASE}/SHA256SUMS-408482
sha256sum -c SHA256SUMS-408482     # must print: bloch-db-snapshot-408482.tar.gz: OK

mkdir -p ./bloch-data
tar xzf bloch-db-snapshot-408482.tar.gz -C ./bloch-data   # restores ./bloch-data/db

# 2) start — it boots at the snapshot's tip and syncs the small gap forward
./target/release/bloch --data-dir ./bloch-data \\
  --listen /ip4/0.0.0.0/tcp/16110 \\
  --peer /ip4/45.32.154.137/tcp/16110</code></pre>
    <div class="prose">
      <p class="small">The snapshot excludes node identity, so your node generates its own. This is a <strong>trust-the-operator bootstrap</strong> — you trust the snapshot's chain instead of verifying it from genesis, an honest disclosed tradeoff you can now avoid entirely by syncing from genesis. <strong>Always verify the SHA-256 and signature before trusting it.</strong> Add <code>--mine</code> once it has caught up to mine on the tip. Published to <a href="downloads.html">downloads</a>.</p>
    </div>
  </div>
</section>

<section aria-labelledby="relay-h">
  <div class="wrap">
    <p class="kicker" id="relay-h">Step 3 · Run a relay node</p>
    <h2>A non-mining node that validates and relays.</h2>
<pre><code>./target/release/bloch \\
  --data-dir ./bloch-data \\
  --listen /ip4/0.0.0.0/tcp/16110 \\
  --rpc-bind 127.0.0.1 --rpc-port 16210</code></pre>
    <div class="prose">
      <p><strong>Network selection:</strong> the current build connects to <strong>the live network — the chain designated mainnet beta</strong> — directly with the command above. (Older builds needed a historical <code>--testnet</code> flag to select the live chain; if your build's <code>--help</code> shows a network flag, match whatever network your bootstrap peer uses.) Network selection does not change the PoW regime: the difficulty-driven k-ramp (k=4 today, rising with hashrate) applies either way.</p>
      <p>The flags shown are also the defaults, spelled out so you can change them deliberately:</p>
    </div>
    <dl>
      <div class="defrow"><dt><code>--data-dir</code></dt><dd>Where the chain lives: RocksDB block/UTXO storage, the persisted known-peers list, and node identity keys. Default <code>./bloch-data</code>, relative to where you launched the node. Delete it to start fresh.</dd></div>
      <div class="defrow"><dt><code>--listen</code></dt><dd>The libp2p P2P multiaddr your node accepts peers on. Default <code>/ip4/0.0.0.0/tcp/16110</code>. This is the address other testers will use to bootstrap from <em>you</em>.</dd></div>
      <div class="defrow"><dt><code>--max-peers</code></dt><dd>Maximum inbound peer connections. Default <code>50</code>. <strong>Raise it on a bootstrap/hub node</strong> (e.g. <code>--max-peers 500</code>) so newcomers aren't dropped once it fills up — a leaf node can leave it at the default. Non-consensus operator knob (see the <a href="releases.html">peering release notes</a>).</dd></div>
      <div class="defrow"><dt><code>--rpc-bind</code> / <code>--rpc-port</code></dt><dd>JSON-RPC over HTTP. Defaults to <code>127.0.0.1:16210</code> — local only, on purpose. Exposing RPC publicly (<code>--rpc-public</code>) is dangerous when unauthenticated; if you must, set <code>--rpc-api-key</code>.</dd></div>
      <div class="defrow"><dt>Ports</dt><dd><code>16110/tcp</code> P2P · <code>16111/tcp</code> P2P WebSocket · <code>16210/tcp</code> RPC (keep local) · <code>16310/tcp</code> Prometheus metrics (only with <code>--metrics</code>).</dd></div>
    </dl>
  </div>
</section>

<section aria-labelledby="mine-h">
  <div class="wrap">
    <p class="kicker" id="mine-h">Step 4 · Or run a miner</p>
    <h2>Solo-mine on the mainnet beta.</h2>
<pre><code># make a miner address first (only the public address is used to mine):
./target/release/bloch-cli newwallet ~/miner-wallet.json   # prints: Address: bloch1q…

./target/release/bloch --mine \\
  --miner-address bloch1q…YOUR_ADDRESS \\
  --data-dir ./bloch-data \\
  --listen /ip4/0.0.0.0/tcp/16110 \\
  --peer /ip4/45.32.154.137/tcp/16110</code></pre>
    <div class="prose">
      <p>Adding <code>--mine</code> makes the node brute-force Module-SIS solutions (under the current ramp gate — <strong>k=4 today</strong>, rising toward k=8 as hashrate grows) and attach the solution vector as each block's PoW witness, with the coinbase paid to <code>--miner-address</code>. Mining via the node is <strong>solo only</strong>: Stratum V1/V2 pool mining is disabled because the hash-PoW share protocol has no field for a lattice solution vector — a SIS-native pool dialect exists separately (see <a href="pool.html">Pool</a>).</p>
      <p>To be blunt about the economics: the coins you mine carry <strong>no value claim</strong> — no price, no market, no listing — on a nascent, low-hashrate network that is <strong>51%-attackable</strong>. The ramp's k is a <strong>structural filter, not a security claim</strong> — raising k adds no cryptographic hardness at β=q/16; what mining actually contributes is <strong>cumulative hashcash work</strong>, the only real security source. Mine to exercise the machinery and add hashrate to a young network, not as an investment.</p>
    </div>
  </div>
</section>

<section aria-labelledby="check-h">
  <div class="wrap">
    <p class="kicker" id="check-h">Step 5 · Check it's alive</p>
    <h2>Query the node over RPC.</h2>
<pre><code># with the bundled CLI (defaults to 127.0.0.1:16210):
./target/release/bloch-cli getnetworkinfo
./target/release/bloch-cli getblockcount

# or raw JSON-RPC over HTTP:
curl -s -X POST http://127.0.0.1:16210/ \\
  -H 'content-type: application/json' \\
  -d '{"jsonrpc":"2.0","id":1,"method":"getnetworkinfo","params":[]}'</code></pre>
    <div class="prose">
      <p><code>getnetworkinfo</code> reports version, network (current builds still report the legacy string <code>testnet</code> for the live mainnet-beta chain — a rename ships in a later release), peer count, and sync state. Other read methods include <code>getblockcount</code>, <code>getdaginfo</code>, <code>getmempoolinfo</code>, <code>getpeerinfo</code>, <code>getblockbyheight</code>, and <code>getbalance</code>. Optional Prometheus metrics: add <code>--metrics</code> and scrape <code>127.0.0.1:16310</code>.</p>
    </div>
  </div>
</section>

<section aria-labelledby="peer-h">
  <div class="wrap">
    <p class="kicker" id="peer-h">Step 6 · Peering</p>
    <h2>Every node is a seed. No node is privileged.</h2>
    <div class="prose">
      <p>The shipped seed list is <strong>empty — literally <code>DEFAULT_SEEDS = []</code> in the source</strong>. That is the ethos, honestly applied: no foundation-run bootstrap servers, no DNS seeds yet (a TODO in the code), no node with a special role. The flip side, stated just as honestly: <strong>your node will sit alone until you give it a peer.</strong> This step shows exactly how to give it one, so anyone — with zero prior context — can join.</p>

      <h3>First, what a peer address (multiaddr) looks like</h3>
      <p>You bootstrap by handing your node the <strong>multiaddr</strong> of any node already on the network. A multiaddr is just a slash-separated recipe for "how to reach this machine". You will only ever need these two shapes:</p>
    </div>
<pre><code>/dns4/&lt;hostname&gt;/tcp/16110     # reach a peer by DNS name
/ip4/&lt;a.b.c.d&gt;/tcp/16110       # reach a peer by raw IPv4 address
#     └── who ──────┘ └─port┘   16110 is the default P2P port</code></pre>
    <div class="prose">
      <p>That address is simply the other node's <code>--listen</code> address as seen from your side of the network — nothing more. Now use it.</p>

      <h3>The one-line way to join, right now</h3>
      <p>To break the cold-start, here is <strong>one node Postern keeps online</strong> for the mainnet beta. Point your node at it and you are on the network:</p>
    </div>
<pre><code>./target/release/bloch \\
  --data-dir ./bloch-data \\
  --listen /ip4/0.0.0.0/tcp/16110 \\
  --peer /ip4/45.32.154.137/tcp/16110</code></pre>
    <div class="warnpanel" role="note">
      <h3>Honest note: that node is a convenience, not an authority</h3>
      <p>The address above is <strong>one Postern-operated node offered purely to break the cold-start</strong> — it is <strong>not</strong> a privileged seed. <code>DEFAULT_SEEDS</code> is still empty in the source, it is <strong>not</strong> hard-coded into any build, it does <strong>not</strong> gate consensus, and <strong>if it vanished the network would continue unchanged.</strong> Do not treat it as official infrastructure — the ownerless protocol has none. It is a starting line, not a gatekeeper: <strong>peer with others too</strong>, and the moment you are connected, <em>your</em> node is a seed for the next person.</p>
    </div>
    <div class="prose">
      <h3>Confirm you actually connected</h3>
      <p>Give it a few seconds, then ask your node who it is talking to. The peer count should climb above zero and your height should start catching up to the network:</p>
    </div>
<pre><code>./target/release/bloch-cli getpeerinfo      # peer_count &gt; 0 means you're in
./target/release/bloch-cli getnetworkinfo   # watch "peers" and "blocks" rise</code></pre>
    <div class="prose">
      <h3>After the first contact, it runs itself</h3>
      <p><code>--peer</code> can be repeated to dial several nodes at once, and DNS names are resolved automatically. Once you have <em>any</em> connection, <strong>peer exchange (PEX)</strong> takes over: your node learns more peers from the ones it already knows, persists them in the data dir, and redials them on every restart — so you only ever need one good address once. Prefer more than one bootstrap peer? Add a friend's node, or one shared in the community channel, on its own <code>--peer</code> line.</p>
      <p>For LAN or single-machine experiments, add <code>--allow-private-peers</code> so RFC1918/loopback addresses (like a second node at <code>/ip4/127.0.0.1/tcp/16110</code>) are accepted. And if you have <em>no</em> peer to dial at all, start an island: run one miner and one relay pointing at each other. On a network this young — very few nodes, stated plainly — every new peer measurably matters.</p>
    </div>
    <div class="warnpanel" role="note">
      <h3>Recent peering upgrade — past the ~50-node wall</h3>
      <p>A bootstrap node used to cap at a hardcoded 50 peers and drop newcomers, and fresh miners could fork from genesis. Fixed with non-consensus knobs (<code>--max-peers</code>, <code>--dns-seed</code>) and a mining-readiness/IBD-latch guard. What changed and how to set up correctly: <a href="releases.html">Release notes&nbsp;→</a> · <a href="/Bloch-Peering-50-Node-Fix.pdf">root-cause PDF&nbsp;↓</a>.</p>
    </div>
    <div class="warnpanel" role="note">
      <h3>Why the network wasn't growing past ~50 nodes — and how to set up correctly</h3>
      <p>A bootstrap node used to cap out at a hardcoded <strong>50 peers</strong> and drop every newcomer, and fresh miners forked from genesis instead of syncing. Both are now addressed with non-consensus operator knobs (<code>--max-peers</code>, <code>--dns-seed</code>, and a sync-before-mine guard). The full root-cause write-up and the correct setup procedure:</p>
      <p><strong><a href="/Bloch-Peering-50-Node-Fix.pdf">Peering &amp; the ~50-node wall — root cause &amp; fix (PDF)&nbsp;↓</a></strong> — unaudited engineering note.</p>
    </div>
  </div>
</section>

<section aria-labelledby="docker-h">
  <div class="wrap">
    <p class="kicker" id="docker-h">Alternative · Docker &amp; Fly.io</p>
    <h2>Containerized, if you prefer.</h2>
    <div class="prose">
      <p>The repository ships a <code>Dockerfile</code> (digest-pinned base images, non-root user, core dumps disabled) exposing <code>16110</code>, <code>16111</code>, <code>16210</code>, and <code>16310</code>. Build and run from the repo root:</p>
    </div>
<pre><code>docker build -t bloch-sis .

docker run -d --name bloch \\
  -p 16110:16110 -p 127.0.0.1:16210:16210 \\
  -v bloch-data:/bloch-data \\
  bloch-sis \\
  --rpc-bind 0.0.0.0 --rpc-port 16210 \\
  --listen /ip4/0.0.0.0/tcp/16110 \\
  --data-dir /bloch-data</code></pre>
    <div class="prose">
      <p>Inside the container RPC must bind <code>0.0.0.0</code> to be reachable; the <code>-p 127.0.0.1:16210:16210</code> mapping keeps it local to your host. Add <code>--mine</code> to the arguments to mine, and <code>--peer &lt;multiaddr&gt;</code> to bootstrap.</p>
      <p>The repo also carries a <code>fly.toml</code> for Fly.io (it runs the node with <code>--mine</code> on a persistent volume). From the repo root:</p>
    </div>
<pre><code>flyctl launch --copy-config --no-deploy   # first time: creates the app
flyctl volumes create bloch_data --size 30 --region &lt;your-region&gt;
flyctl deploy</code></pre>
    <p class="prose small">See <code>deploy/fly/README.md</code> in the protocol repo for the full walkthrough — and remember what the machine will be doing: mining coins that carry no value claim, on unaudited mainnet-beta research software.</p>
  </div>
</section>

<section aria-labelledby="report-h">
  <div class="wrap">
    <p class="kicker" id="report-h">What to do with what you find</p>
    <h2>Break it, then tell everyone.</h2>
    <div class="prose">
      <p>Useful contributions, in rough order of value: attacks on the Module-SIS PoW design (even on-paper, against the canonical regime), consensus and reorg edge cases, difficulty (ASERT-Lattice) manipulation, IBD and networking failures, build failures on your platform. File issues in the protocol repository — publicly, since there is no private steward to whisper to.</p>
    </div>
    <div class="warnpanel" role="note">
      <h3>One last time</h3>
      <p><strong>Mainnet beta — unaudited.</strong> The Module-SIS gate is a <strong>difficulty-driven k-ramp</strong> (node v0.1.0-alpha2): <strong>k=4 today, climbing 5→6→7→8 as the network's own difficulty grows and easing back if hashrate falls</strong> — a structural filter, not a security claim (real security is cumulative hashcash work), and no security is claimed. <strong>Very few nodes / low hashrate → 51%-attackable.</strong> Not a security, not an asset — no sale, no listing, no price. 17% founder premine disclosed. You are running research, not joining an economy. If anyone tells you otherwise, they are not us — <a href="disclaimer.html">the disclaimer wins</a>.</p>
    </div>
  </div>
</section>
`;

/* ------------------------------------------------------------------
   Vestnik node-setup assistant — the ONE interactive widget on the site.
   Opt-in chat scoped to node setup; posts to the same-origin Cloudflare
   Pages function /api/node-helper (which holds the API key server-side).
   ------------------------------------------------------------------ */
const NODE_CHAT_HTML = `
<section aria-labelledby="vk-h">
  <div class="wrap">
    <p class="kicker" id="vk-h">Need a hand?</p>
    <h2>Ask the Vestnik node-setup assistant.</h2>
    <div class="prose">
      <p>Stuck on a step? This is a small, opt-in helper scoped to <strong>one job: helping you build, run, peer, mine with, and troubleshoot a Bloch node</strong>. It answers node-setup questions only — nothing about price, investment, or anything off-topic.</p>
      <p><strong>Honest note:</strong> unlike the rest of this site, this widget runs a little JavaScript and — <em>only when you send a message</em> — forwards your question to a language-model backend (Anthropic, via a same-origin function on this site) to compose a reply. It stores nothing. <strong>Don't paste secrets</strong> (wallet seeds, keys) into it. If you'd rather not use it, everything you need is written out in the steps above.</p>
    </div>
    <div class="vestnik">
      <div class="vk-head"><span class="vk-dot" aria-hidden="true"></span><span class="vk-title">Vestnik · node setup</span><span class="vk-scope">node questions only</span></div>
      <div class="vk-log" id="vk-log" role="log" aria-live="polite"></div>
      <form class="vk-form" id="vk-form">
        <textarea class="vk-input" id="vk-input" rows="1" placeholder="e.g. how do I connect my node to the network?" autocomplete="off" aria-label="Ask about node setup"></textarea>
        <button class="vk-send" id="vk-send" type="submit">Send</button>
      </form>
    </div>
    <noscript><p class="vk-note">The assistant needs JavaScript. Follow the written steps above, or enable JS for this page.</p></noscript>
    <p class="vk-note">Unaudited, mainnet-beta research software. The assistant can be wrong — always verify against <code>bloch-cli</code> output and the steps above.</p>
  </div>
</section>
`;

// No literal backticks / \${} in this source (it is emitted verbatim inside a
// <script> and pinned by CSP hash). Backticks are built via fromCharCode(96).
const NODE_CHAT_JS = `
(function(){
  var log=document.getElementById('vk-log');
  var form=document.getElementById('vk-form');
  var input=document.getElementById('vk-input');
  var send=document.getElementById('vk-send');
  if(!log||!form||!input||!send)return;
  var FENCE=String.fromCharCode(96,96,96);
  var msgs=[];
  function bubble(role,text){
    var cls='vk-msg '+(role==='user'?'vk-user':(role==='sys'?'vk-sys':'vk-bot'));
    var b=document.createElement('div'); b.className=cls;
    var segs=String(text).split(FENCE);
    for(var i=0;i<segs.length;i++){
      if(i%2===1){
        var s=segs[i]; var nl=s.indexOf('\\n');
        if(nl>=0 && s.slice(0,nl).indexOf(' ')<0) s=s.slice(nl+1);
        var pre=document.createElement('pre'); var code=document.createElement('code');
        code.textContent=s.replace(/\\n$/,''); pre.appendChild(code); b.appendChild(pre);
      } else if(segs[i]){
        var span=document.createElement('span'); span.textContent=segs[i]; b.appendChild(span);
      }
    }
    log.appendChild(b); log.scrollTop=log.scrollHeight; return b;
  }
  bubble('bot','Hi — I am the Vestnik node-setup assistant. I only help with building, running, peering, mining, and troubleshooting a Bloch-SIS-PoW node. Ask me anything about setting one up.');
  var busy=false;
  function ask(q){
    if(busy||!q)return; busy=true; send.disabled=true;
    msgs.push({role:'user',content:q}); bubble('user',q);
    var wait=bubble('sys','thinking...');
    fetch('/api/node-helper',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({messages:msgs})})
      .then(function(r){return r.json();})
      .then(function(d){
        if(wait.parentNode)log.removeChild(wait);
        if(d&&d.reply){msgs.push({role:'assistant',content:d.reply}); bubble('bot',d.reply);}
        else{bubble('sys',(d&&d.error)||'Something went wrong. Please try again.');}
      })
      .catch(function(){ if(wait.parentNode)log.removeChild(wait); bubble('sys','Network error — please try again.'); })
      .then(function(){ busy=false; send.disabled=false; input.focus(); });
  }
  form.addEventListener('submit',function(e){ e.preventDefault(); var q=input.value.trim(); if(!q)return; input.value=''; ask(q); });
  input.addEventListener('keydown',function(e){ if(e.key==='Enter'&&!e.shiftKey){ e.preventDefault(); var q=input.value.trim(); if(!q)return; input.value=''; ask(q); } });
})();
`;

/* ============================================================
   PAGE: Mining / Pool
   ============================================================ */

const POOL = `
<section class="hero">
  <div class="wrap">
    <div class="rule" aria-hidden="true"></div>
    <p class="kicker">Mining · solo first, pool optional</p>
    <h1>Mining, and the reference pool.</h1>
    <p class="lede">Solo mining on the Bloch-SIS-PoW mainnet beta needs no pool: <code>bloch --mine</code> mines standalone, and a found block pays you the whole reward. The pool described here is <strong>strictly optional</strong> — a piece of <strong>reference, non-production</strong> software whose only honest purpose is smoothing variance for small miners. It never touches Postern's revenue, and it never sells or lists the coin.</p>
    <div class="warnpanel" role="note">
      <h3>Read before pointing hashrate anywhere</h3>
      <ul>
        <li><strong>Mainnet beta — a designation, not a security claim.</strong> The chain is <strong>unaudited</strong> (audit contracted, not done); the Module-SIS gate is a <strong>difficulty-driven k-ramp</strong> (node v0.1.0-alpha2) — k=4 today, climbing toward k=8 as the network's own difficulty grows and easing back if hashrate falls. A structural filter, not a security claim: real security is cumulative hashcash work.</li>
        <li><strong>Very few nodes, low hashrate → 51%-attackable.</strong> The coins you mine — solo or pooled — carry <strong>no value claim</strong>: not a security, not an asset, no sale, no listing, no price. 17% founder premine disclosed. <a href="disclaimer.html">Full disclaimer</a>.</li>
        <li>Mine to exercise the machinery and strengthen a young network — <strong>not as an investment</strong>. Use at your own risk.</li>
      </ul>
    </div>
  </div>
</section>

<section aria-labelledby="solo-h">
  <div class="wrap">
    <p class="kicker" id="solo-h">Solo vs pool</p>
    <h2>Solo is the default. The pool only changes the variance.</h2>
    <div class="prose">
      <p><strong>Solo mining works standalone.</strong> A node started with <code>--mine</code> (see <a href="run-a-node.html">run a node</a>) mines on its own; if it finds a block, you get the entire reward. No pool, no account, no third party.</p>
      <p><strong>The pool is optional, and it does exactly one honest thing: it smooths variance.</strong> A small miner who would find a solo block once a month can instead earn a proportional slice of every block the pool finds, via <strong>PPLNS</strong> share accounting. The <strong>expected income is the same</strong> (minus any pool fee) — only the variance changes. If your hashrate is large enough that solo variance doesn't hurt, <strong>solo mine</strong>.</p>
    </div>
  </div>
</section>

<section aria-labelledby="fiftyone-h">
  <div class="wrap">
    <p class="kicker" id="fiftyone-h">The part pool marketing never says</p>
    <h2>A big pool is an attack on the network it serves.</h2>
    <div class="warnpanel" role="note">
      <h3>Do not concentrate hashrate — spread it, or run solo</h3>
      <p>A pool that grows past <strong>~51% of network hashrate is a 51%-attack vector against the very network it serves</strong> — regardless of the operator's intentions, it is a single point of coercion, failure, and censorship. On a network this small, that line is uncomfortably close. So, the opposite of pool marketing, on purpose:</p>
      <ul>
        <li><strong>Do not point your hashrate at the biggest pool.</strong> Prefer small pools — and leave any pool that is approaching a majority of the network.</li>
        <li><strong>Run your own pool.</strong> The reference below is MIT-licensed precisely so forking and self-hosting is easy — it exists so there can be <em>many</em> independent pools, not one.</li>
        <li><strong>Solo mine when you can.</strong> Every solo miner is a decentralization win.</li>
      </ul>
      <p>The reference daemon prints this warning at startup, the dashboard shows it in a banner, and the dashboard <strong>actively estimates the pool's share of network hashrate</strong> — escalating into an explicit “move your hashrate elsewhere” warning as it nears the majority line. Forks are asked to keep all three. <strong>Do not operate a pool at a scale approaching 51% of the network.</strong></p>
    </div>
  </div>
</section>

<section aria-labelledby="ref-h">
  <div class="wrap">
    <p class="kicker" id="ref-h">The reference pool</p>
    <h2>bloch-pool — open-source, reference, non-production.</h2>
    <p class="prose">The protocol repository ships a reference pool in its <code>pool/</code> directory — a standalone cargo workspace, deliberately independent of the node so it can be vendored and forked. It is <strong>reference code, unaudited, and not hardened for production</strong> — the same honest status as the chain itself. Three binaries:</p>
    <div class="grid">
      ${card("bloch-pool", "The pool daemon: SIS-native stratum dialect (the classic Stratum V1 protocol has no field for the 256-coefficient solution vector every Bloch block carries), PPLNS share accounting with a maturity-gated credit lifecycle, a JSONL-journaled restart-surviving ledger, JSON-RPC upstream to a Bloch node, and the honest dashboard.", [B_PROTO, B_UNAUD])}
      ${card("bloch-pool-miner", "A reference CPU miner that doubles as runnable protocol documentation. Signs the pool's address-ownership challenge, keeps its nonce cursor across jobs — intentionally a single-connection smoke-test client, not a performance miner.", [B_PROTO, B_UNAUD])}
      ${card("bloch-pool-keyshard", "Shamir 2-of-3 seed-recovery utility for the pool wallet (any 2 shares reconstruct; one alone reveals nothing). Honest label, exactly as the tool prints it: key recovery for disaster resilience — NOT threshold signing.", [B_PROTO, B_UNAUD])}
    </div>
    <div class="prose" style="margin-top:1.6rem">
      <p>Two honesty rules are built in. First, <strong>share validation is the real consensus verifier</strong>, pointed at a softer target — and shares are credited only to an address the connection has <em>proved</em> it controls (a hybrid ML-DSA-65&nbsp;‖&nbsp;Falcon-1024 signature over a per-session challenge, the same scheme as consensus). Second, <strong>the accounting never overstates what the pool holds</strong>: a found block is recorded <em>pending</em> and credits are booked only once it is canonical at <code>--confirm-depth</code> (default 10); an orphaned block's pending credit is dropped, never booked. Every share and block event is journaled and replayed at startup, so a restart cannot erase owed balances — and an operator cannot “time” restarts to harvest an empty PPLNS window.</p>
      <p class="small">One more label worth keeping straight: the PoW is <strong>not lattice-hard</strong>. Bloch-SIS-PoW is SHAKE-256 cumulative-work hashcash with a Module-SIS <em>structural gate</em>; pool shares are plain hash-difficulty shares, and no lattice bit-security number attaches to any of this.</p>
    </div>
  </div>
</section>

<section aria-labelledby="runpool-h">
  <div class="wrap">
    <p class="kicker" id="runpool-h">Running it</p>
    <h2>A pool is just two binaries and a node.</h2>
    <div class="prose">
      <p>Build from the protocol source tree (see <a href="run-a-node.html">run a node</a> for cloning and prerequisites — the repository address is <code>gitlab.com/blochsispow-group/BlochSISPoW-project</code>, rendered as text because the ownerless protocol has no official site). You need a Bloch node with RPC enabled; the pool talks to it over <code>getblocktemplate</code> / <code>submitblock</code> / <code>getblockhash</code> and depends only on two lean protocol crates, not the full node.</p>
    </div>
<pre><code>cd pool
cargo build --release
cargo test</code></pre>
    <p class="prose">The pool daemon — every flag spelled out so you change it deliberately:</p>
<pre><code>RUST_LOG=info bloch-pool \\
  --pool-address bloch1q...      # required: where block rewards land
  --node-rpc http://127.0.0.1:16210 \\
  --fee-bps 0 \\                  # pool fee in basis points; capped at 1000 (10%)
  --share-bits 2100ffff \\        # compact share difficulty (hex); fixed, no vardiff
  --pplns-window 4096 \\          # PPLNS window size, in shares
  --confirm-depth 10 \\           # blocks credit only once canonical at this depth
  --journal bloch-pool.journal \\ # JSONL ledger journal ("" = memory-only, testing)
  --listen 0.0.0.0:3335 \\        # miner-facing stratum
  --dashboard 127.0.0.1:8650 \\   # dashboard HTTP (keep it loopback or proxied)
  --refresh-secs 5 \\             # template poll interval (well under the 30 s block time)
  --coinbase-tag bloch-pool-ref/v0.1
  # --no-auth-proof              # disable the address-ownership proof (not recommended)</code></pre>
    <p class="prose">And the reference miner, pointed at it:</p>
<pre><code>bloch-pool-miner \\
  --address bloch1q...           # required: your payout address
  --auth-seed &lt;hex 32B seed&gt; \\   # wallet seed controlling --address (signs the
                                 # pool's ownership challenge; required unless the
                                 # pool runs --no-auth-proof)
  --auth-index 0 \\               # optional: diversified-address index for the seed
  --pool 127.0.0.1:3335 \\
  --max-shares 0 \\               # exit after N accepted shares (0 = forever)
  --burst 200000                 # candidates per burst between socket polls</code></pre>
    <div class="warnpanel" role="note">
      <h3>About <code>--auth-seed</code> — the seed never leaves your machine over the network, but mind local exposure</h3>
      <p>The ownership proof signs a one-time challenge locally; the seed itself is <strong>never sent to the pool</strong>. But a seed passed as a command-line flag is visible <strong>locally</strong> — in <code>ps</code>/process listings and your shell history — to anything running as your user. So: prefer a <strong>mining-only seed</strong> (an address you use only for payouts, not your main wallet), and supply it from a file or environment variable rather than typing it inline where the shell records it. Your funds' real protection is key custody, not this flag.</p>
    </div>
    <p class="prose small">Note the default fee is <strong>0%</strong> — the fee is an operator setting, not a project revenue stream. Consistent with everything else on this site: <strong>no revenue line of this project touches the token.</strong></p>
  </div>
</section>

<section aria-labelledby="connect-h">
  <div class="wrap">
    <p class="kicker" id="connect-h">How to connect</p>
    <h2>Connecting a miner, end to end.</h2>
    <div class="prose">
      <p>A short terminal walkthrough against the reference deployment at <code>postern-pool.fly.dev</code> (stratum <code>postern-pool.fly.dev:3335</code>, dashboard at <code>https://postern-pool.fly.dev</code>): create a wallet with <code>bloch-cli newwallet</code>, build <code>bloch-pool-miner</code>, connect with your payout address and your wallet seed as <code>--auth-seed</code> (the pool requires an ownership proof by default — the seed signs a one-time challenge and is never sent over the network — though, as noted above, prefer a mining-only seed supplied via file/env since a CLI flag is visible locally in <code>ps</code> and shell history), then watch shares land on the dashboard.</p>
    </div>
    <div class="videos">
      <figure>
        <video controls playsinline preload="metadata">
          <source src="/media/postern-pool-connect-v2.mp4" type="video/mp4">
        </video>
        <figcaption class="small"><strong>How to connect a miner to the Postern pool — tutorial (1:32, narrated, subtitled).</strong> Everything shown is <strong>reference, non-production</strong> software on the <strong>unaudited mainnet beta</strong>; the coin is <strong>worth nothing by design</strong>. Solo mining (<code>bloch --mine</code>) remains the default — don't concentrate hashrate on any single pool, this one included.</figcaption>
      </figure>
    </div>
  </div>
</section>

<section aria-labelledby="custody-h">
  <div class="wrap">
    <p class="kicker" id="custody-h">Custody, stated honestly</p>
    <h2>Procedural M-of-N — not threshold signing.</h2>
    <div class="prose">
      <p>Pooled mining unavoidably means the pool address briefly custodies the coinbase until disbursement. Here is the honest state of the art for Bloch, with nothing pretended:</p>
      <ul>
        <li><strong>Cryptographic threshold signing is not available.</strong> Bloch's hybrid ML-DSA-65&nbsp;‖&nbsp;Falcon-1024 signatures have no practical MPC/threshold construction today (2027+ research), and the chain is strictly single-signature P2PKH with <strong>no script system</strong> — on-chain k-of-n multisig needs a consensus change, roadmapped separately as GIP-008. Nothing in this pool pretends otherwise.</li>
        <li><strong>What ships instead is procedural:</strong> <code>bloch-pool-keyshard</code> splits the pool wallet's seed into 3 Shamir shares (any 2 reconstruct — the field math is the vetted <code>sharks</code> crate, not hand-rolled), one per custodian. This is <strong>seed recovery for disaster resilience</strong>: at recovery, and at every signing, the seed exists whole in one process on one machine. Run both offline.</li>
        <li><strong>The pool daemon itself is keyless by design.</strong> Credits are ledger entries, not payments; disbursing them is a manual wallet transaction under a documented <strong>dual-control procedure</strong> — the signing wallet lives on an isolated machine, two people approve every disbursement against the journal, and the custodied float is kept minimal by disbursing frequently.</li>
      </ul>
    </div>
  </div>
</section>

<section aria-labelledby="dash-h">
  <div class="wrap">
    <p class="kicker" id="dash-h">The honest dashboard</p>
    <h2>A dashboard built to make lying harder.</h2>
    <div class="prose">
      <p>The running daemon serves a self-contained HTML dashboard (no external assets) and the same numbers as JSON at <code>/api/stats</code>. To be clear about what that means: <strong>it is a server UI — it exists only where someone is running a pool.</strong> The reference deployment at <code>postern-pool.fly.dev</code> serves one; any other pool's dashboard is whoever runs that pool — verify accordingly, or run your own.</p>
      <p>What it shows is exactly what the ledger knows — per-miner shares, confirmed credits, the estimated next-block split, blocks with their pending/confirmed/orphaned status, node-rejected submissions, and the <strong>explicit pool take</strong> — plus:</p>
      <ul>
        <li>an <strong>honest luck panel</strong>: expected blocks (Σ share-work / block-work) versus blocks actually found, pool-wide and per miner — so bad luck and <em>statistical block withholding</em> are visible instead of indistinguishable;</li>
        <li>a rolling <strong>share-of-network estimate</strong> that escalates into the “move your hashrate elsewhere” warning as the pool nears the 51% line;</li>
        <li>node health — seconds since the last good template; new miners get no work from a stale tip.</li>
      </ul>
      <p class="small">Two small honesty details: sat amounts in <code>/api/stats</code> are serialized as <strong>strings</strong>, because JS numbers lose exactness past 2^53 and an honesty tool must not do approximate arithmetic on debts; and the work-rate figure is labeled <strong>candidates/s</strong>, not hash/s, because a candidate (seed expansion + SIS residual gate + aux hash) is what it actually measures.</p>
    </div>
  </div>
</section>

<section aria-labelledby="limits-h">
  <div class="wrap">
    <p class="kicker" id="limits-h">Honest limits</p>
    <h2>What this reference is not.</h2>
    <div class="prose">
      <ul>
        <li><strong>Not audited, not production.</strong> Same status as the chain itself. Advisor-flagged holes have been closed, but it has not seen adversarial production traffic.</li>
        <li><strong>The operator is still trusted.</strong> Nothing stops a fork from lying on its dashboard — verify pools by their behavior, or run your own. The ownership proof, session caps, rate caps, and bounded queues harden the <em>miner-facing</em> side only.</li>
        <li><strong>No vardiff.</strong> One fixed share difficulty for every miner: fast miners waste round trips, slow miners wait long between shares.</li>
        <li><strong>The journal is append-only and grows forever.</strong> Rotation and compaction are the operator's problem (one JSON object per line, trivially archivable).</li>
        <li><strong>Confirmation is canonical-hash-at-height</strong> — on a GhostDAG, a conservative approximation of coinbase spendability, not a full blue-set proof.</li>
        <li><strong>No TLS</strong> on stratum or the dashboard — if you expose either beyond localhost, terminate TLS at a reverse proxy, and keep the dashboard bound to loopback unless deliberately published.</li>
        <li><strong>Single upstream node, no failover</strong> — a down node means the pool logs, withholds stale work from new miners, and retries.</li>
        <li><strong>Manual payouts only.</strong> The daemon has no wallet and no keys, by design.</li>
      </ul>
    </div>
    <div class="warnpanel" role="note">
      <h3>One last time</h3>
      <p><strong>Mainnet beta — unaudited.</strong> The Module-SIS gate is a <strong>difficulty-driven k-ramp</strong> (k=4 today, rising with hashrate — a structural filter, not a security claim). <strong>Low hashrate → 51%-attackable</strong> — which is exactly why this page tells you to spread hashrate, run solo, and never feed a majority pool. The coin is <strong>not a security and not an asset</strong> — no sale, no listing, no price, no value claim; 17% founder premine disclosed. Use at your own risk — <a href="disclaimer.html">the disclaimer wins</a>.</p>
    </div>
  </div>
</section>
`;

/* ============================================================
   PAGE: Disclaimer
   ============================================================ */

const DISCLAIMER = `
<section class="hero">
  <div class="wrap narrow">
    <div class="rule" aria-hidden="true"></div>
    <p class="kicker">Disclaimer &amp; legal</p>
    <h1>The full text, in plain language.</h1>
    <p class="lede">This page is the canonical version of every warning on this site. If anything elsewhere ever seems to promise more than this page does, this page wins.</p>
  </div>
</section>

<section aria-labelledby="d1">
  <div class="wrap narrow prose">
    <h2 id="d1">1. Beta software — unaudited, no warranty</h2>
    <p>Everything Postern Labs publishes today is <strong>pre-production beta software</strong>, provided <strong>“as is”, without warranty of any kind</strong>, express or implied, including merchantability, fitness for a particular purpose, and non-infringement — as stated in the MIT and Apache-2.0 licenses that govern it.</p>
    <p><strong>No third-party security audit has been performed</strong> on any Postern product or on the underlying protocol. An audit is <strong>contracted but not done yet</strong> — until it is delivered, everything here remains unaudited. Internal review and passing test suites are not an audit. Nothing here is a certified security product.</p>

    <h2 id="d2" style="margin-top:2.4rem">2. Do not protect real secrets with it yet</h2>
    <p>This beta exists for <strong>evaluation</strong>: to be read, built, reproduced, and broken. It does not exist to protect anything you cannot afford to lose. Until the audits gate open:</p>
    <ul>
      <li>do <strong>not</strong> store real passwords or secrets in the Vault;</li>
      <li>do <strong>not</strong> send sensitive files through the Courier;</li>
      <li>do <strong>not</strong> rely on the Messenger, Keys, Panic Lock, or any other component for real operational security;</li>
      <li>do <strong>not</strong> treat the OS images or the desktop app as hardened production systems.</li>
    </ul>
    <p>If your safety depends on your tools, use established, audited tools. We will tell you — on this page — when that calculus changes.</p>
    <p><strong>The AI features are the least-private path, by construction.</strong> The apps that talk to Claude do so with <strong>your own Anthropic key</strong>, calling <code>api.anthropic.com</code> directly — no Postern server is in that path, but the prompt is still <strong>processed by Anthropic, a third party</strong>, and voice input additionally goes to your browser's speech vendor (Google on Chrome/Chromium). Sending a prompt to a cloud AI is sending your data to a third party; do not send anything through it that would be unsafe for that third party to see. The exact destinations, the voice exception, and Tolmach's less-private subscription-proxy tier are laid out in full under <a href="products.html#ai-h">AI interactions · bring your own key</a> — that page governs; if anything here seems to promise more privacy, it wins.</p>

    <h2 id="d3" style="margin-top:2.4rem">3. The mainnet beta — what the label does and does not mean</h2>
    <p>The Bloch-SIS-PoW protocol now runs a <strong>mainnet beta</strong>. That is a <strong>designation, not a security claim</strong>: the network is live and persistent, and it is <strong>nascent, unaudited, and easy to attack</strong>. Precisely:</p>
    <ul>
      <li><strong>The fixed k=8 gate is retired — the gate is now a difficulty-driven k-ramp</strong> (node v0.1.0-alpha2). The earlier fixed k=8 hardening multiplied mining difficulty ~4096× with no security gain (β=q/16 is the trivial regime at any k) and choked block production at low hashrate. Under the ramp, <strong>k=4 applies today</strong> — below a future activation height, so every node upgrades first with no fork — then k climbs 5→6→7→8 as the network's own ASERT difficulty sustains above spaced thresholds, and eases back if hashrate falls (so block time stays ~30s). The ramp restores liveness; it adds no cryptographic hardness, and <strong>no security is claimed</strong>.</li>
      <li><strong>The security source is cumulative SHAKE-256 hashcash work — hashrate × time.</strong> The Module-SIS gate (at any k) is a structural filter that binds work to a lattice form — it is not the security source. The real hardness lever is a smaller β plus the outstanding audit, not k.</li>
      <li><strong>Very few nodes and low hashrate → 51%-attackable.</strong> A modest adversary could out-mine and reorganize this chain today. Do not treat confirmations as final in any way that matters.</li>
      <li><strong>Unaudited.</strong> A third-party audit is <strong>contracted but not done yet</strong>; the concrete-security (no-shortcut) analysis and the IACR ePrint publication for open expert review are still outstanding. “Mainnet beta” does not mean those gates have been passed — it means the chain is live while they are pursued.</li>
    </ul>
    <p>Nothing on this site calls this network “secure” or “production”. If any other page ever seems to, this section wins.</p>

    <h2 id="d4" style="margin-top:2.4rem">4. The coin is not a security and not an asset</h2>
    <p><strong>Do not attach value to the coin.</strong> The protocol's native coin exists as a consensus mechanism, not as an investment:</p>
    <ul>
      <li><strong>No token sale</strong> — past, present, or planned;</li>
      <li><strong>No listing effort, no market-making, no price</strong> — and no cooperation with anyone attempting to create one;</li>
      <li><strong>No promoter</strong> — the protocol is ownerless: no foundation, no curator, no official website (see <a href="postern-vs-bloch.html">Postern &amp; Bloch</a>);</li>
      <li><strong>No expectation of profit</strong> should be formed from anything Postern Labs says or sells — Postern's revenue is protection and support, never the token.</li>
    </ul>
    <p>Coins on the mainnet beta carry <strong>no value claim</strong>: there is no price and no market, the network is <strong>51%-attackable</strong>, and the difficulty-driven k-ramp (k=4 today) is a structural filter, not a security claim by itself. Not for investment. Use at your own risk.</p>

    <h2 id="d5" style="margin-top:2.4rem">5. The premine, disclosed in full</h2>
    <p>The single fact a skeptic will weigh against “ownerless”, kept visible on purpose: the protocol's genesis allocates a <strong>17% founder premine</strong>, subject to a <strong>10-year cliff</strong> and a <strong>40-year vesting schedule</strong>, and structurally passive — it confers no governance power, no protocol privileges, and is backed by zero sale and zero listing effort. We state it here so nobody discovers it as a surprise.</p>

    <h2 id="d6" style="margin-top:2.4rem">6. Built vs designed — what actually runs</h2>
    <p>Labelled the same way everywhere on this site:</p>
    <ul>
      <li><strong>Built · tests pass</strong> — the Rust product cores (<code>crates/postern-*</code>) compile and their test suites pass;</li>
      <li><strong>Built · hosted + signed · QEMU boot pending</strong> — the Postern OS node ISO (x86_64): the image builds, is hosted and release-signed, but has not yet been observed to boot (no QEMU serial log or <code>.evidence</code> sidecar is published), so no boot claim is made and it is certainly not hardware-tested;</li>
      <li><strong>Built · hosted + signed · QEMU boot pending</strong> — the Postern OS desktop ISO: same status — it builds, is hosted and release-signed, and has not yet been observed to boot, so no boot claim is made;</li>
      <li><strong>Reference prototype</strong> — working front-ends (the self-contained web apps, the Tauri desktop app) that demonstrate the design; also the <strong>signed, published-but-never-device-booted</strong> “Postern for postmarketOS” apk packages — three signed apks in a live aarch64 repo, on an alpha build key (signed ≠ reproducible ≠ attestable);</li>
      <li><strong>Design / spec</strong> — documented plans (the Android container, the cloud and enterprise editions) that are not running software yet. The mobile OS image has moved past this: it is built, hosted, and release-signed, though not yet boot-tested.</li>
    </ul>
    <p>If a claim isn't true yet, we phrase it as the plan — and a plan is all it is. <strong>The signed x86_64 ISOs and the aarch64 mobile image are hosted with checksums and minisign signatures, and three signed apks (the postmarketOS community edition) are hosted on a live aarch64 repo; building from source remains the strongest verification, and anything not yet hosted still installs from source.</strong></p>

    <h2 id="d7" style="margin-top:2.4rem">7. Licenses</h2>
    <p>Postern products are permissively licensed — <strong>MIT / Apache-2.0, per crate</strong> — with no GPL/AGPL code embedded anywhere in the products. The free build is always buildable from source. The ownerless protocol carries its own licensing in its own repository (<code>gitlab.com/blochsispow-group/BlochSISPoW-project</code>).</p>

    <h2 id="d8" style="margin-top:2.4rem">8. This website</h2>
    <p>This site is static, self-contained, and makes <strong>no network requests</strong>: no analytics, no tracking, no external fonts, scripts, or images, and a Content-Security-Policy that forbids outbound connections. What you just read is everything it does.</p>
    <p><strong>Geo-restriction (HTTP 451).</strong> The <strong>hosted</strong> site returns <strong>HTTP 451 (Unavailable For Legal Reasons)</strong> to visitors it identifies as coming from jurisdictions under OFAC <strong>comprehensive</strong> sanctions. Be clear about what that is and is not: it is a <strong>hosting-service control only</strong>, applied at our edge to this website; it is a coarse IP-based measure that a VPN or Tor can evade, and it makes no claim to be exhaustive. Crucially, it does <strong>not — and cannot — gate the ownerless Bloch-SIS-PoW protocol</strong> (a permissionless peer-to-peer network with no operator) <strong>or the open-source software</strong> (MIT / Apache-2.0, buildable from source by anyone). It restricts who we serve this page to; it restricts nothing about the commons.</p>

    <h2 id="d9" style="margin-top:2.4rem">9. Pricing &amp; how Postern Labs stays funded</h2>
    <p>Postern Labs is a company, and a company needs revenue — to keep building and to pay for the audit. We would rather disclose the plan now, plainly, than surprise you with it later. <strong>None of this is live yet, and there is no price on anything today.</strong> This is a forward-looking signal, for your awareness.</p>
    <ul>
      <li><strong>Mobile stays free forever; only Postern Desktop moves to freemium — and your data is never held hostage.</strong> Our published promise "personal editions stay free regardless" <strong>still holds for mobile</strong>: the mobile OS and every personal app on mobile are <strong>free forever</strong> — mobile is our free adoption channel and we are not touching it. The one thing that changes is <strong>Postern Desktop (the personal desktop suite)</strong>, which now <strong>reserves the right to require a license in the future</strong>: each desktop install is <strong>free for 24 months</strong>, after which a personal key is required to keep receiving <strong>updates and premium features</strong>. We are saying this loudly, up front, because narrowing a published promise quietly would be exactly the dark pattern we refuse to run. We are doing it as fairly as we can: <strong>every desktop install gets 2 full years free</strong>, and <strong>every existing desktop install is grandfathered a full 2-year window from the changeover date</strong> — we are choosing to give <strong>24 months of notice-and-grace</strong>, so no one is cut short. The key gates features and updates, <strong>never access to your own encrypted data</strong>: decrypt, read, export, and safety actions (Panic Lock) <strong>always work</strong> — key or not, expired or not; expiry fails <strong>open</strong> to a read-only grace mode, never a lockout. We still do not monetize the personal user's <strong>data</strong>: <strong>no selling or sharing your data, no telemetry, and no ads that track you</strong> — that promise stands. What is new, and we are stating it plainly: the free versions (all personal mobile apps, and Postern Desktop during its free window) <strong>may show advertising — but only the privacy-preserving kind</strong>: <strong>contextual, non-tracking</strong> ads chosen from nothing but the current screen or content, with <strong>no user profile, no advertising or device ID, no third-party ad SDK that phones home, no telemetry, and no data leaving your device</strong>, always <strong>clearly labeled</strong> as ads. <strong>Surveillance, programmatic, behavioral, and tracking-based advertising are forbidden</strong> — that is the only ad model consistent with Postern. Ads <strong>never</strong> appear in security-critical flows — <strong>Panic Lock, Vault decrypt/export, and backup are always ad-free</strong> — and <strong>the paid Postern Desktop key removes ads entirely</strong> (part of what the key buys). The coin is <strong>never</strong> monetized. The key is verified <strong>offline</strong>; we store only a salted hash and dates, never your identity. <em>(None of this is live yet — there is no billing integration and no price today, the per-install free-window clock is not built, and <strong>no ad system is built, no ad network is integrated, and no ad placements ship</strong>; this is the announced model plus the offline-key mechanism, not a running payment or advertising system.)</em></li>
      <li><strong>Business &amp; corporate use is free today.</strong> A company with a <strong>DUNS number</strong> can <a href="/license/master">generate a free 6-month master license</a> right now — <strong>unlimited users</strong>, which the master can then split into sub-accesses. The <strong>6 months is the window while we structure the revenue model</strong>; after it, a license will be required for continued business/corporate use. A lighter <strong>business freemium</strong> tier (up to <strong>3 desktops for 2 years</strong>) needs no DUNS. There is <strong>no live price today</strong>, any future charge is billed in <strong>fiat, never the coin</strong>, and the license is <strong>verified offline with no telemetry</strong> — we store only your DUNS and the dates to honor it. Personal <strong>mobile</strong> apps stay free forever; only <strong>Postern Desktop</strong> follows the freemium model above — 2 years free, then a key — and the coin is never involved in any of it.</li>
      <li><strong>Other intended revenue lines:</strong> priority / SLA support, deployment and signed/notarized build channels, attestation-verification services, and grants. These sell <strong>work and assurance</strong>, not your data.</li>
    </ul>
    <p><strong>The hard rule across all of it:</strong> revenue never comes from the coin (it is worthless and not a security), and never from <strong>selling or surveilling</strong> the personal user. Contextual, non-tracking advertising in the free versions is allowed because it takes <strong>nothing</strong> from you — no profile, no tracking, no data off your device; anything that would surveil or profile you is not. You pay Postern Labs (or view a labeled contextual ad) for <strong>protection, support, and provable integrity — never for a coin, and never with your privacy.</strong> This is not a commitment to any specific price or date, and it is not legal or financial advice.</p>

    <p class="small dim" style="margin-top:2rem">Nothing on this site is legal, financial, or investment advice. This disclaimer accompanies a public beta and will be revised as the audit gates are passed — changes will appear here first.</p>
  </div>
</section>
`;

const BLOCH_NOTICE = `
<section class="hero">
  <div class="wrap narrow">
    <div class="rule" aria-hidden="true"></div>
    <p class="kicker">Compliance · the ownerless protocol</p>
    <h1>The <code>blochprotocol.com</code> domain.</h1>
    <p class="lede">Postern Labs does <strong>not</strong> maintain, and <strong>cannot</strong> maintain, a website at <code>blochprotocol.com</code>. This page states why, and it is published here — on Postern's own product site — precisely because Postern does not speak for the protocol.</p>
  </div>
</section>

<section aria-labelledby="why-h">
  <div class="wrap narrow prose">
    <p class="kicker" id="why-h">Why</p>
    <h2>The protocol has no owner and no official site.</h2>
    <p><strong>Bloch-SIS-PoW</strong> is an <strong>ownerless</strong> protocol: by design it has no owner, no foundation, no curator, and <strong>no official website</strong> — it is software plus a documented RPC/API surface, and nothing more. <strong>Postern Labs is merely one builder among many</strong> on that neutral base.</p>
    <div class="warnpanel" role="note">
      <h3>For compliance, Postern Labs declares it is NOT</h3>
      <ul>
        <li>the <strong>owner</strong> of the Bloch-SIS-PoW protocol;</li>
        <li>a <strong>representative</strong> of the protocol, its users, or its community;</li>
        <li>a <strong>holder of any prerogatives</strong> — no authority, no privileged role, no power to decide, to speak officially, or to administer the protocol.</li>
      </ul>
    </div>
    <p>Operating a site at <code>blochprotocol.com</code> would falsely imply an official, representative, or proprietary position that Postern Labs <strong>does not hold and does not claim</strong>. Doing so would contradict both the protocol's principles and Postern Labs' compliance posture. Postern Labs therefore <strong>does not operate</strong> that site.</p>
  </div>
</section>

<section aria-labelledby="where-h">
  <div class="wrap narrow prose">
    <p class="kicker" id="where-h">Where the protocol lives</p>
    <h2>Software, in the open — maintained by its community, not by Postern.</h2>
    <p>The protocol is public software. Its source lives at <code>gitlab.com/blochsispow-group/BlochSISPoW-project</code> — shown here as <strong>text</strong>, not as an endorsing link, precisely because there is no official site to recommend. Any website about the protocol, if one exists, should be created and maintained by the <strong>community</strong> — never by Postern Labs, which does not speak for the protocol.</p>
    <p>Postern Labs' <strong>product</strong> site is this one, <code>posternlabs.com</code> — and it concerns only Postern's products, leaving the protocol as what it is: an ownerless commons. Postern's only economic tie to the base is a disclosed, structurally passive <strong>17% founder premine</strong>, which confers no control, administration, or representation. See <a href="postern-vs-bloch.html">Postern &amp; Bloch-SIS-PoW</a> for the full separation.</p>
    <p class="small dim">This is a statement of position by Postern Labs, not legal advice. Bloch-SIS-PoW is a pre-mainnet, unaudited, zero-security beta; its coin is not a security and not an asset.</p>
  </div>
</section>

<section aria-labelledby="ffg-h">
  <div class="wrap narrow prose">
    <p class="kicker" id="ffg-h">Roadmap · declared target (not shipped)</p>
    <h2>FFG-BFT finality — activation target: block <code>1,000,000</code>.</h2>
    <div class="warnpanel" role="note">
      <h3>Declared roadmap target — NOT built</h3>
      <p>This is a direction, not a shipped feature. FFG-BFT exists today only as a <strong>compiling, tested design scaffold</strong> — <strong>not integrated into the node, not audited, and not running</strong>. Nothing activates at block 1,000,000 yet. It is a <strong>candidate</strong> improvement to the ownerless base: nobody mandates it, and it activates only if node operators adopt it. (Only shipped items go on the changelog — this lives here, as roadmap.)</p>
    </div>
    <p><strong>What it is.</strong> A post-quantum <strong>finality overlay</strong> on the ownerless Bloch base — not a base-consensus change. Individual <strong>ML-DSA-65 (FIPS 204)</strong> signatures, with <strong>no BLS, DKG, or aggregation</strong>. The committee is the <strong>miners, weighted by hashrate</strong> (block-share); a checkpoint finalizes when signatures cover <strong>&gt; 2/3 of the epoch's frozen weight</strong>, and anchors to the base as an <strong>ordinary zero-value transaction</strong>. Coins do not vote; hashrate does — the base gains no operator.</p>
    <p><strong>The target.</strong> Block <code>1,000,000</code> (~6.8 months of runway at 30-second blocks) is the proposed, coordinated, height-gated activation — when it is ready, not before.</p>
    <p><strong>The path — each step gates the next:</strong></p>
    <ol>
      <li><strong>Base stable</strong> — sync/convergence holding one chain (prerequisite).</li>
      <li><strong>Integrate into the node</strong> — committee, weighted quorum, BFT0 checkpoint anchoring, wired into consensus and RPC.</li>
      <li><strong>Test</strong> — unit, integration, and a full-epoch testnet dry-run.</li>
      <li><strong>Audit</strong> — third-party review; a finality overlay is safety-critical.</li>
      <li><strong>Coordinated deploy</strong> — adopted by a super-majority of hashrate ahead of the height, so activation is fork-safe.</li>
      <li><strong>Activate at block 1,000,000.</strong> No "it's ready" claim before then.</li>
    </ol>
    <div class="warnpanel" role="note">
      <h3>Honest limits</h3>
      <p>This is <strong>not settlement finality</strong>. The base is a mainnet beta (k-forgeable, 51%-attackable, unaudited), so overall security is <strong>min(base, committee)</strong>. Hashrate-weighted finality is <strong>only as decentralized as the hashrate</strong> — today concentrated. It <strong>mitigates</strong> 51% (raising the bar 51%&nbsp;→&nbsp;67%, plus no-deep-reorg finality below each checkpoint); it does not eliminate it. The <strong>BLCH coin is not a security and not an asset</strong>.</p>
    </div>
    <p class="small dim">Design: <code>docs/specs/POSTERN-FFG-BFT-FINALITY.md</code> · scaffold <code>bft/postern-bft-finality</code> · activation constant <code>FFG_ACTIVATION_HEIGHT = 1_000_000</code>. A candidate improvement to an ownerless protocol — Postern speaks for no one.</p>
  </div>
</section>`;

/* ============================================================
   PAGE: PosternDex
   ============================================================ */

const POSTERNDEX = `
<section class="hero">
  <div class="wrap">
    <div class="rule" aria-hidden="true"></div>
    <p class="kicker">PosternDex · design preview — inert</p>
    <h1>A DEX on Bloch — designed, not live.</h1>
    <p class="lede">PosternDex is a <strong>Uniswap-v2-model AMM</strong> planned for the ownerless Bloch-SIS-PoW base — constant-product pools, permissionless liquidity, third-party liquidity providers earning swap fees. <strong>It is a design, not a running exchange.</strong> No pools exist, no swaps happen, and — most importantly — it <strong>will not be activated until the chain is secure enough to trade on.</strong></p>
    <div class="warnpanel" role="note" style="margin-top:1.4rem">
      <p style="margin:0"><strong>⛔ Activation gate — read this.</strong> A DEX lets people trade value, and a chain that can be reorganised can have its trades rewritten and its liquidity double-spent. Bloch today is <strong>low-hashrate, 51%-attackable, and unaudited</strong> (its gate is a difficulty-driven k-ramp — k=4 now, a structural filter, not security). Putting value on it now would be dishonest and unsafe.</p>
      <p style="margin:.7rem 0 0"><strong>PosternDex stays completely inert until Bloch's network hashrate crosses a published security threshold</strong> — high enough that a 51% reorg (which would let an attacker rewrite swaps and drain liquidity) is economically impractical — <strong>together with</strong>: the difficulty-driven <strong>k-ramp fully climbed to k=8</strong>, <strong>checkpoint finality</strong> live, a <strong>third-party audit</strong> of the AMM and its L2, and <strong>legal review</strong>. The exact hashrate number is set and published at audit time, not guessed here. Until every one of those clears, this page is the whole product.</p>
    </div>
  </div>
</section>

<section aria-labelledby="dx-what">
  <div class="wrap">
    <p class="kicker" id="dx-what">The model</p>
    <h2>Uniswap v2, on a post-quantum PoW base.</h2>
    <p class="prose">The design is deliberately unoriginal: <strong>reuse the battle-tested Uniswap v2 AMM</strong> (Factory / Pair / Router), not reinvent it. Pools hold two tokens and enforce <code>x·y=k</code>; a <strong>0.30% swap fee accrues to the liquidity providers</strong>; anyone can create a pool or become an LP — that is the "third parties allocate liquidity and are remunerated as AMMs" part, and it is permissionless by construction.</p>
    <p class="prose">The one thing Bloch lacks that Ethereum gives Uniswap for free is a place to <em>run</em> contracts — Bloch is pure PoW/UTXO with no EVM. So PosternDex runs on an <strong>EVM Layer-2</strong> (designed separately) that anchors to Bloch as ordinary transactions and needs no consensus change; real Uniswap contracts then deploy unchanged. (An ownerless-native covenant path on Bloch L1 is the long-term alternative.)</p>
    <p class="prose small dim">Layer discipline: the pool primitive and the token standard are the <strong>ownerless base</strong> (anyone deploys, Postern holds no privilege); the PosternDex <strong>interface</strong> and the L2 <strong>sequencer</strong> are <strong>owned Postern products</strong> — they have operators. Same rule as everywhere: <em>anything with a "who runs it?" answer is a product.</em></p>
  </div>
</section>

<section aria-labelledby="dx-bridge">
  <div class="wrap">
    <p class="kicker" id="dx-bridge">Scope of v1</p>
    <h2>No bridge. Native tokens only.</h2>
    <p class="prose">v1 needs <strong>no bridge</strong> — it trades tokens that are <strong>native to Bloch</strong>. That deliberately avoids the single most-exploited construct in crypto (asset-custody bridges have lost billions). A separate, later, <strong>optional</strong> bridge module — designed but gated behind the same security/audit/legal wall — could one day wrap outside assets (BTC/ETH/USDT); <strong>USDT would be inherently double-custodial</strong> (Tether + a federation) and labelled so. None of that is part of the DEX itself.</p>
    <p class="prose small dim">Honest limit: native tokens have <strong>no external value</strong> today (BLCH is worthless-by-design; most issued tokens are test/worthless). A working DEX is not a DEX with valuable assets until the chain matures.</p>
  </div>
</section>

<section aria-labelledby="dx-honest">
  <div class="wrap">
    <p class="kicker" id="dx-honest">Standing disclosures</p>
    <h2>What this is not.</h2>
    <ul class="prose">
      <li><strong>Not a yield/investment product.</strong> LP fees are a variable cut of swap fees for providing liquidity — a service, not interest, not a promised return; <strong>impermanent loss</strong> is real. No leverage, no lending, no farming, no APY vaults — the constructs that turn a DEX into an unregistered security or a rug factory are <strong>deliberately not built</strong>.</li>
      <li><strong>Not a token sale.</strong> BLCH is <strong>not a security and not an asset</strong> — no sale, no listing, no price; Postern's revenue never touches the token, and any protocol fee (off by default) would be fiat-equivalent utility, never a buyback/burn.</li>
      <li><strong>Listing ≠ endorsement.</strong> Anyone can issue a token; most are worthless or malicious. A pool existing says nothing about a token's value or safety.</li>
      <li><strong>Unaudited, beta, zero-value</strong> — and it will say so on every screen until the activation gate clears.</li>
    </ul>
    <p class="prose small">This is <strong>not investment advice</strong> and <strong>not legal advice</strong>. Postern Labs is in the process of legal incorporation; a DEX + fee-earning LPs touch securities and money-transmission law, and legal review is a hard gate.</p>
  </div>
</section>
`;

/* ============================================================
   PAGE: Security
   ============================================================ */

const SECURITY = `
<section class="hero">
  <div class="wrap">
    <div class="rule" aria-hidden="true"></div>
    <p class="kicker">Security · internal audits</p>
    <h1>We audit our own code, out loud.</h1>
    <p class="lede">Postern runs <strong>continuous internal, AI-assisted adversarial code review</strong> across both the ownerless Bloch-SIS-PoW protocol and the owned Postern products — and reports what it finds honestly, including the still-open bits. This is <strong>not</strong> the contracted third-party audit (that is the real gate, and it is still pending); it is the in-house discipline that runs between third-party passes.</p>
  </div>
</section>

<section aria-labelledby="sec-how">
  <div class="wrap">
    <p class="kicker" id="sec-how">How it runs</p>
    <h2>Many auditors, then adversaries.</h2>
    <p class="prose">Each pass fans a fleet of <strong>Claude Opus 4.8 auditors</strong> across partitioned slices of the codebase — crypto, consensus, networking, the shielded pool, the wallet, the file parsers, the desktop command surface, the web apps, the packaging scripts. Every candidate finding is then <strong>adversarially verified against the source</strong> (file:line) before it counts, and every <em>fix</em> is checked by an independent reviewer that tries to break it — <em>"did this actually close the hole, or just compile?"</em>. That adversarial fix-verification is where the value is: on the last pass it caught a subtle <strong>consensus-halt</strong> that the first read missed, which was then fixed too.</p>
  </div>
</section>

<section aria-labelledby="sec-latest">
  <div class="wrap">
    <p class="kicker" id="sec-latest">Latest internal pass — 2026-07</p>
    <h2>What it found, in aggregate.</h2>
    <p class="prose">Roughly <strong>49 findings</strong> across the two codebases, verified against source:</p>
    <ul class="prose">
      <li><strong>2 critical</strong> — both in the protocol (network-layer resource handling and shielded-transaction accounting). <strong>Remediated in code + adversarially re-verified.</strong></li>
      <li><strong>6 high</strong> — protocol (mining-submission validation, transport framing, peer-string handling, the reorg consensus-halt) and products (a web-app output-encoding issue, a messenger encryption-tier check). <strong>All remediated in code.</strong></li>
      <li><strong>~11 medium / ~30 low</strong> — parser resource limits, desktop URL pinning, supply-chain signing, secret zeroization, governance edge-cases. Remediated or scheduled.</li>
    </ul>
    <p class="prose">The products' fixes are <strong>live</strong>; the protocol's fixes are <strong>committed and pending deployment to the running nodes</strong> (the ownerless protocol is upgraded the Bitcoin way — node operators adopt, nobody forces it).</p>
  </div>
</section>

<section aria-labelledby="sec-ops">
  <div class="wrap">
    <p class="kicker" id="sec-ops">Node operators — action required</p>
    <h2>A security update is available. Update your node.</h2>
    <div class="warnpanel" role="note">
      <p style="margin:0"><strong>If you run a Bloch-SIS-PoW node, update now.</strong> The fixes from the latest internal audit — including the two criticals and the reorg consensus-halt — are <strong>merged into the protocol's main branch</strong>. The protocol is ownerless and upgraded the Bitcoin way: <strong>nobody can force you</strong>, but an un-updated node is exposed to a remote single-packet crash and a reorg-halt.</p>
      <p style="margin:.7rem 0 0"><strong>To update:</strong> <code>git pull</code> the latest <code>main</code> from <code>gitlab.com/blochsispow-group/BlochSISPoW-project</code>, rebuild (<code>cargo build --release</code>), and restart your node. No data migration or config change is needed. The project's own public demo nodes are being redeployed with the fix.</p>
    </div>
  </div>
</section>

<section aria-labelledby="sec-reports">
  <div class="wrap">
    <p class="kicker" id="sec-reports">Technical reports</p>
    <h2>The full findings, per finding.</h2>
    <p class="prose">The full technical audit reports — every finding with its file:line, attack scenario, and fix, plus a post-audit remediation banner — are published <strong>as the corresponding fixes go live</strong>, so a report never doubles as a working weapon against an un-patched target:</p>
    <ul class="prose">
      <li><strong><a href="/Postern-Security-Audit.pdf">Postern products — Security Audit (PDF)&nbsp;↓</a></strong> — <strong>published.</strong> The products' fixes are deployed (web-app fixes live; desktop/crate fixes in the downloadable products), so the details are safe to release. 33 findings, all high/medium remediated + adversarially re-verified.</li>
      <li><strong><a href="/Bloch-Security-Audit.pdf">Bloch-SIS-PoW protocol — Security Audit (PDF)&nbsp;↓</a></strong> — <strong>published.</strong> The public demo nodes are updated with the fix and operators are notified (here, on the explorer, and in the community), so the details are now safe to release. 16 findings incl. 2 criticals (network-decode OOM, shielded-note counterfeiting) and a reorg consensus-halt — all remediated + adversarially re-verified (one narrow reorg race scheduled for hardening).</li>
      <li><strong><a href="/Bloch-Postern-Security-Review-2.pdf">Internal Security Review — Report #2 (PDF)&nbsp;↓</a></strong> — <strong>published.</strong> A second internal round: the <strong>networking/consensus hardening</strong> that root-caused why the chain stopped producing blocks and why new nodes couldn't join (the 50-peer cap, the IBD latch, gossip-delivery gaps — operator fixes live), plus the honest security-tier note on the Module-SIS gate's status (since superseded by the difficulty-driven k-ramp of node v0.1.0-alpha2 — see <a href="releases.html">Releases</a>). Follows responsible disclosure — owned-product findings whose fixes aren't yet deployed are held. Verification evidence re-run this round: <strong>1579/1579</strong> NoporIS parity, <strong>70/70</strong> gate-store, <strong>109/109</strong> Porog kernel, <strong>79/79</strong> crypto — reference tests, not a security proof.</li>
    </ul>
    <p class="prose small" style="margin-top:1rem">Found a vulnerability? See the RFC 9116 policy at <a href="/.well-known/security.txt">/.well-known/security.txt</a> and <a href="/SECURITY.md">/SECURITY.md</a>. Nothing here is audited or safe: the chain runs the <strong>difficulty-driven k-ramp (k=4 today — a structural filter, not security), still 51%-attackable and unaudited</strong>, everything is a <strong>beta</strong>, and internal AI-assisted review is <strong>not a substitute for the contracted third-party audit</strong>. Do not protect real value with any of this yet.</p>
  </div>
</section>
`;

const RELEASE_PEERING = `
<section class="hero">
  <div class="wrap">
    <div class="rule" aria-hidden="true"></div>
    <p class="kicker">Release notes · changelog</p>
    <h1>What shipped.</h1>
    <p class="lede">A plain, unaudited log of what actually went live — not plans. In-progress work is deliberately kept off this page until it ships. Newest first.</p>
    <div class="warnpanel" role="note">
      <h3>Honesty baseline</h3>
      <ul>
        <li><strong>Mainnet beta — not a security claim.</strong> The Module-SIS gate is a <strong>difficulty-driven k-ramp</strong> (k=4 today, rising with hashrate — a structural filter, not a security claim); the chain is <strong>unaudited</strong> and 51%-attackable. The coin is <strong>not a security and not an asset</strong> — no price, no value claim.</li>
        <li><strong>Ownerless protocol.</strong> Bloch changes are non-consensus operator conveniences shipped as candidate improvements any node operator may adopt — nobody mandates them, and Postern speaks for no one. Postern-product changes are owned and operated by Postern.</li>
        <li><strong>Only shipped items appear here.</strong> If it is a branch, a design, or "merged but not deployed," it is not on this page.</li>
      </ul>
    </div>
  </div>
</section>

<section aria-labelledby="freemium-h">
  <div class="wrap">
    <p class="kicker" id="freemium-h">2026-07-18 · Pricing · Postern Desktop</p>
    <h2>Postern Desktop moves to 2 years free, then a key — mobile stays free forever, and here is what it means for your data: nothing.</h2>
    <div class="prose">
      <p>We are narrowing a promise we published. Our stated pricing line was <strong>"personal editions stay free regardless"</strong> — and it <strong>still holds for mobile</strong>: the mobile OS and every personal app on mobile stay <strong>free forever</strong>, our free adoption channel, untouched. The only thing changing is <strong>Postern Desktop (the personal desktop suite)</strong>, which now <strong>reserves the right to require a license in the future</strong>: each desktop install is <strong>free for 2 years</strong> (the adoption on-ramp), after which a <strong>personal key</strong> keeps <strong>updates and premium features</strong> coming. We are announcing this <strong>loudly and in plain language</strong> because narrowing a published promise quietly would be exactly the kind of dark pattern we refuse to run.</p>
      <p><strong>What changes for your data: nothing.</strong> The key gates updates and premium features — <strong>never access to your own encrypted data</strong>. Decrypt, read, and export of every vault, wallet, credential, message, and backup you already have <strong>always work</strong> — key or not, expired or not — and safety actions like <strong>Panic Lock</strong> always fire. After 2 years with no key a desktop app enters a <strong>read-only grace mode</strong>: it fails <strong>open</strong>, never into a lockout, and your data is never held hostage.</p>
      <p><strong>One more change, stated plainly: free versions may now show ads — but only the privacy-preserving kind.</strong> Free versions (all personal mobile apps, and Postern Desktop during its free window) <strong>may show contextual, non-tracking ads</strong>: chosen from nothing but the current screen, with <strong>no profile, no advertising or device ID, no third-party ad SDK, no telemetry, and no data leaving your device</strong>, always clearly labeled. <strong>Surveillance, behavioral, programmatic, and tracking-based ads are forbidden.</strong> Ads <strong>never</strong> appear in Panic Lock, Vault decrypt/export, or backup, and <strong>the paid Postern Desktop key removes ads entirely</strong>. Our promise of "no ads that track you" is unchanged — this narrows it to "contextual, no-tracking only," it does not walk it back.</p>
    </div>
    <dl>
      <div class="defrow"><dt>Ads: contextual and non-tracking only</dt><dd>Free versions may show ads based only on the current screen — <strong>no tracking, no profile, no device ID, no telemetry, nothing leaves the device</strong>, always labeled, never in security-critical flows. The <strong>Desktop key removes ads</strong>. Surveillance/behavioral advertising is forbidden.</dd></div>
      <div class="defrow"><dt>Mobile is free forever</dt><dd>Only <strong>Postern Desktop</strong> moves to freemium. The mobile OS and all personal <strong>mobile</strong> apps (Wallet, Vault, Keys, Courier, Seal, Hygiene, Panic, Vestnik, Tor, Quarantine, Telephony, Encrypted Backup, personal Ezekiel 1, …) stay <strong>free forever</strong> (they may carry the same contextual, no-tracking ads).</dd></div>
      <div class="defrow"><dt>Done as fairly as we can</dt><dd>Every desktop install gets <strong>2 full years free</strong>. We are choosing to give <strong>24 months of notice-and-grace</strong> before a key is needed — a generous transition, not a fine-print switch.</dd></div>
      <div class="defrow"><dt>Existing installs grandfathered</dt><dd>Anyone who installed Postern Desktop under the old "stays free" line is <strong>grandfathered a full 2-year window from the changeover date</strong> — you are not cut short.</dd></div>
      <div class="defrow"><dt>No surveillance, no coin</dt><dd>The key is verified <strong>100% offline</strong> — no phone-home, no account, no telemetry; we store only a <strong>salted hash and dates</strong>, never your identity. The coin (BLCH) is <strong>never</strong> monetized and is <strong>not</strong> involved in licensing.</dd></div>
      <div class="defrow"><dt>Not live yet — honest status</dt><dd>This is the <strong>announced model plus the offline-key mechanism</strong>, not a running billing system. <strong>There is no payment integration and no price today, the per-install free-window clock is not built, and no ad system is built — no ad network is integrated and no placements ship.</strong> Everything Postern ships remains an <strong>unaudited reference prototype</strong>. Full detail on the <a href="disclaimer.html#d9">disclaimer §9</a> and the <a href="products.html">product tiers</a>.</dd></div>
    </dl>
  </div>
</section>

<section aria-labelledby="reanchor-h">
  <div class="wrap">
    <p class="kicker" id="reanchor-h">2026-07-16 · Bloch node v0.1.0-alpha3</p>
    <h2>Two consensus fixes the k-ramp exposed — the network converges again.</h2>
    <div class="prose">
      <p>Relaxing the gate back to k=4 (alpha2) un-choked block production — and that surfaced <strong>two latent consensus bugs</strong> that had been masked while the chain crawled: non-mining nodes stopped converging (they <strong>froze on ingest</strong>) and the sole miner ran away. Both are fixed here; both are <strong>backward-safe</strong> — historical blocks validate byte-for-byte, so there is no fork.</p>
    </div>
    <dl>
      <div class="defrow"><dt>Finality checkpoint — unit fix</dt><dd>The finality checkpoint was <strong>computed in blue-score but enforced in height</strong>; once the DAG-width skew passed the checkpoint depth, a node "finalized" a height <strong>above its own tip</strong> and permanently rejected every chain-extending block. It now uses the selected tip's <strong>height</strong>, and a one-time startup clamp heals the poisoned value. Ingesting nodes converge again.</dd></div>
      <div class="defrow"><dt>ASERT difficulty — height-switched re-anchor</dt><dd>ASERT clamped the <strong>absolute</strong> schedule exponent to ±4×, a <em>lifetime</em> cap — difficulty could never exceed 4× the genesis target however much hashrate joined (ASICs/FPGA included). A height-switched <strong>re-anchor</strong> resets the schedule and — only for the re-anchored regime — widens the bound so difficulty <strong>tracks real hashrate</strong>. Blocks below the anchor keep the old bound byte-for-byte.</dd></div>
      <div class="defrow"><dt>Verified live</dt><dd>Two nodes were reset to a shared base and converged on the re-anchored chain, both mining — the finality fix confirmed by nodes <strong>accepting</strong> the blocks they previously froze on. Unaudited; the coin has no value; Bloch is <strong>ownerless</strong> — a candidate release operators adopt, not a mandate.</dd></div>
    </dl>
  </div>
</section>

<section aria-labelledby="kramp-h">
  <div class="wrap">
    <p class="kicker" id="kramp-h">2026-07-16 · Bloch node v0.1.0-alpha2</p>
    <h2>Difficulty-driven k-ramp — the fixed k=8 gate is retired.</h2>
    <div class="prose">
      <p>The Module-SIS residual gate no longer jumps to a fixed <strong>k=8</strong> — which had been misapplied onto the live chain and was choking block production at low hashrate for <strong>no security gain</strong> (the source flags both k=4 and k=8 as the trivial q-ary regime at β=q/16). It now rides the network's own <strong>ASERT difficulty</strong> — the Bitcoin model: more hashrate → higher difficulty → higher k.</p>
    </div>
    <dl>
      <div class="defrow"><dt>k = 4 now, rising with hashrate</dt><dd>k stays 4 below a <strong>future</strong> activation height (every node upgrades first — <strong>no fork</strong>), then rises 5→6→7→8 as sustained difficulty crosses ~8×-spaced thresholds, and <strong>eases back if hashrate falls</strong> (self-healing — a capacity crash can't re-choke the chain). Backward-safe: existing k=8 blocks stay valid (k=8 ⊃ k=4).</dd></div>
      <div class="defrow"><dt>Security is the cumulative work, not k</dt><dd>Raising k is a structural / throughput filter, <strong>not cryptographic hardness</strong> (β=q/16 is trivial-regime at any k∈{4..8}). Real security is <strong>cumulative SHAKE-256 hashcash work = hashrate × time</strong> — which needs a <em>live</em> chain to grow. The real hardness lever is a smaller β plus the outstanding audit, not k.</dd></div>
      <div class="defrow"><dt>Also in v0.1.0-alpha2</dt><dd>The peering upgrade (<code>--max-peers</code>, <code>--dns-seed</code>, <code>--behind-proxy</code>, IBD-latch release, fresh-miner fork guard), the DAG-ordering consensus-halt fix, and the security-audit fixes. Unaudited; the coin has no value; Bloch is <strong>ownerless</strong> — a candidate release operators adopt, not a mandate.</dd></div>
    </dl>
  </div>
</section>

<section aria-labelledby="up-h">
  <div class="wrap">
    <p class="kicker" id="up-h">2026-07-15 · updates</p>
    <h2>Also shipped today.</h2>
    <dl>
      <div class="defrow"><dt>Signed snapshot fast-sync — live</dt><dd>A <strong>signed chain snapshot is published</strong>, so a fresh node can onboard in one pass: download, <strong>verify its SHA-256</strong>, extract, and mine forward. (At the time this shipped, the then-active fixed k=8 gate made genesis sync impractical, so the snapshot was the only practical path; under the k-ramp above, <strong>genesis sync works again and the snapshot is an optional convenience</strong>.) See <a href="snapshot.html">Snapshot sync</a> for the direct download, the published checksum, and a worked node-deploy example. Two independent nodes were brought online from it and are mining.</dd></div>
      <div class="defrow"><dt>Narrated node-setup video</dt><dd>A ~2½-minute narrated walkthrough with English captions — miner address, snapshot download + checksum verify, running with <code>--peer</code>/<code>--mine</code>, and keeping it alive under systemd — now on <a href="index.html">Home</a>, <a href="run-a-node.html">Run a node</a>, and <a href="snapshot.html">Snapshot sync</a>. The written steps stay authoritative.</dd></div>
      <div class="defrow"><dt>Vestnik node-setup assistant</dt><dd>An opt-in chat helper on <a href="run-a-node.html">Run a node</a>, scoped strictly to building, peering, mining, and troubleshooting a Bloch node — nothing else. Its knowledge tracks the current onboarding path — the <strong>difficulty-driven k-ramp with the snapshot as an optional fast-sync</strong> (real CLI verbs, the miner-address step, the verified run command, systemd). It runs the one bit of JavaScript on the site and forwards a question to a language model only when you send it; it stores nothing. Live.</dd></div>
      <div class="defrow"><dt>Reference mining pool — relaunched</dt><dd>The Postern-operated reference pool was rebuilt and redeployed (<code>postern-pool.fly.dev</code>: stratum <code>:3335</code>, dashboard over HTTPS), and the site's connection instructions were corrected to the working endpoint. Fee 0% — no revenue line touches the token. One independent pool among any number; verify or run your own.</dd></div>
      <div class="defrow"><dt>Public bootstrap node — <code>--max-peers 500</code></dt><dd>The demo bootstrap node was redeployed with the raised peer cap, so newcomers are no longer dropped once it fills (see the peering upgrade below). Non-consensus; an external node now connects where it previously could not.</dd></div>
      <div class="defrow"><dt>Site fixes</dt><dd>Added a <a href="pool.html">Pool</a> tab and this <strong>Releases</strong> tab; fixed the Pool nav link (a stale redirect sent it to the home page); corrected the pool endpoint text; refreshed an outbound profile link.</dd></div>
    </dl>
  </div>
</section>

<section aria-labelledby="what-h">
  <div class="wrap">
    <p class="kicker" id="what-h">2026-07-15 · Bloch peering upgrade</p>
    <h2>Past the ~50-node wall — three non-consensus changes.</h2>
    <div class="prose">
      <p>PoW, block validation, serialization, and GhostDAG are <strong>untouched</strong>. The changes are operator knobs and a mining-readiness guard:</p>
    </div>
    <dl>
      <div class="defrow"><dt><code>--max-peers &lt;N&gt;</code></dt><dd>The inbound peer cap was a hardcoded <strong>50</strong> — a bootstrap/hub node dropped every newcomer once full (the "~50-node wall"). It is now an operator setting. The public bootstrap runs <code>--max-peers 500</code>; a leaf node keeps it modest.</dd></div>
      <div class="defrow"><dt><code>--dns-seed &lt;host&gt;</code></dt><dd>Opt-in, Bitcoin-style cold-start: the node resolves a hostname's A/AAAA records and dials them as peers. <code>DEFAULT_SEEDS</code> stays empty — <strong>non-privileged</strong>: run, or point at, any seed you trust.</dd></div>
      <div class="defrow"><dt>Mining-readiness guard</dt><dd>A node told to <em>join</em> a network (has <code>--peer</code>/<code>--dns-seed</code>) no longer mines until it has connected and evaluated the network tip — so a fresh miner can't fork from genesis. Intentional solo/island miners are unaffected. Also fixed an IBD latch that left a synced node paused forever (<code>is_syncing</code> only cleared on a message no peer ever sends).</dd></div>
    </dl>
  </div>
</section>

<section aria-labelledby="setup-h">
  <div class="wrap">
    <p class="kicker" id="setup-h">Setup, correctly</p>
    <h2>Join, sync, then mine.</h2>
<pre><code># 1) join &amp; sync FIRST (relay)
./target/release/bloch --data-dir ./bloch-data \\
  --listen /ip4/0.0.0.0/tcp/16110 \\
  --peer /dns4/&lt;a-reachable-node&gt;/tcp/16110

# 2) confirm it caught up
./target/release/bloch-cli getpeerinfo      # peer_count &gt; 0
./target/release/bloch-cli getblockcount    # reaches the tip

# 3) only then add --mine  (a hub also adds --max-peers 500)</code></pre>
    <p class="prose small">Full root-cause write-up: <a href="/Bloch-Peering-50-Node-Fix.pdf">Peering &amp; the ~50-node wall (PDF)&nbsp;↓</a>. Building/running instructions: <a href="run-a-node.html">Run a node</a>.</p>
  </div>
</section>
`;

const SNAPSHOT_SYNC = `
<div class="wrap" style="padding-top:1.1rem">
  <div class="warnpanel" role="note">
    <h3>Syncing from genesis is not possible — and the older snapshot is now a dead end</h3>
    <p>Block bodies below roughly height <strong>376,422</strong> were pruned on every node and are unrecoverable, so a node started empty asks for block 0 and no peer can answer. Worse, the previously published <code>bloch-db-snapshot.tar.gz</code> ends at <strong>394,361</strong> while peers have since pruned below <strong>~394,913</strong> — a node restored from it stalls forever in the ~550-block gap, with connected peers and a healthy-looking log.</p>
    <p><strong>Use the snapshot below (height 408,482).</strong> It starts above the gap and syncs normally. Verified end-to-end on a real machine, not assumed.</p>
    <p class="small dim">The mechanism worth understanding: pruning deletes bodies below <code>tip &minus; 10,000</code>, so a published snapshot must be refreshed <strong>before</strong> the network prunes past the height it ends at. Miss that window and the path from snapshot to tip breaks silently. This network hit exactly that.</p>
  </div>
</div>

<section class="hero">
  <div class="wrap">
    <div class="rule" aria-hidden="true"></div>
    <p class="kicker">Sync the easy way</p>
    <h1>Set up your node from a snapshot.</h1>
    <p class="lede">Under the difficulty-driven k-ramp (node v0.1.0-alpha2), a brand-new node <strong>can sync from genesis</strong> — the historical chain validates again. The signed snapshot is the <strong>optional fast path</strong>: skip the initial block download in <strong>one command</strong>, boot straight at the tip, and mine forward.</p>
    <div class="cta-row">
      <a class="btn primary" href="${OS_BASE}/bloch-db-snapshot-408482.tar.gz">⬇ Download snapshot &mdash; height 408,482 (233&nbsp;MB)</a>
      <a class="btn" href="${OS_BASE}/SHA256SUMS">SHA256SUMS</a>
    </div>
    <p class="small" style="margin:.6rem 0 0;color:var(--text-dim)">Pruned chain at the current tip. <strong>Verify the SHA-256 before use</strong> (<code>sha256sum -c SHA256SUMS</code>). Restore + start commands below.</p>
  </div>
</section>

<section aria-labelledby="video-h">
  <div class="wrap">
    <p class="kicker" id="video-h">Watch it first</p>
    <h2>The whole setup, in one short video.</h2>
    <figure style="margin:1.2rem 0 0">
      <video controls playsinline preload="metadata" poster="/media/bloch-node-setup-v3-poster.png" style="width:100%;max-width:100%;border:1px solid var(--border);border-radius:10px;background:#000">
        <source src="/media/bloch-node-setup-v3.mp4" type="video/mp4">
        <track kind="subtitles" srclang="en" label="English" default src="/media/bloch-node-setup-v3.vtt">
      </video>
      <figcaption class="small dim" style="margin-top:.6rem"><strong>Snapshot sync — set up a Bloch node in ~3 min</strong> · narrated · English captions. The video is an overview — the <strong>written steps below are authoritative</strong>. Unaudited research chain; the coin has no value.</figcaption>
    </figure>
  </div>
</section>

<section aria-labelledby="why-h">
  <div class="wrap">
    <p class="kicker" id="why-h">Why you might want this</p>
    <h2>Genesis sync works — the snapshot just skips the wait.</h2>
    <div class="prose">
      <p><strong>The Module-SIS gate is now a difficulty-driven k-ramp</strong> (node v0.1.0-alpha2): k=4 today, rising toward k=8 as the network's own difficulty grows. Under the ramp's k=4 rule, <strong>the historical chain validates again</strong> — the earlier fixed k=8 gate, which made the k=4-mined history unvalidatable from genesis, is retired. So a brand-new node has <strong>two valid paths</strong>:</p>
      <ol>
        <li><strong>Sync from genesis</strong> — full validation from block zero, the strongest-trust path. Just point the node at a peer and let the initial block download run.</li>
        <li><strong>Restore the signed snapshot</strong> — a pruned capture of a current node's chain state at the tip. Your node skips the initial block download, boots at the tip, and mines forward under the current ramp (k=4 today). A convenience, not a requirement.</li>
      </ol>
    </div>
    <div class="warnpanel" role="note">
      <h3>Honest tradeoff</h3>
      <p>The snapshot path is a <strong>trust-the-operator bootstrap</strong>: you trust the snapshot's chain rather than verifying it yourself from genesis. That is a real, disclosed weakening versus full validation — you can avoid it entirely by syncing from genesis — so you should <strong>verify the SHA-256 and the signature</strong> before trusting any snapshot, and prefer one you can cross-check. Unaudited, zero-value research chain; the coin carries <strong>no value claim</strong>.</p>
    </div>
  </div>
</section>

<section aria-labelledby="how-h">
  <div class="wrap">
    <p class="kicker" id="how-h">How to do it</p>
    <h2>One command to be on the network.</h2>
    <div class="prose"><p>You need the built <code>bloch</code> binary first (see <a href="run-a-node.html">Run a node</a>, steps 1–2). Then:</p></div>
<pre><code># 1) download the signed snapshot + checksums, and verify
curl -O ${OS_BASE}/bloch-db-snapshot-408482.tar.gz
curl -O ${OS_BASE}/SHA256SUMS
curl -O ${OS_BASE}/SHA256SUMS-408482
sha256sum -c SHA256SUMS-408482     # must print: bloch-db-snapshot-408482.tar.gz: OK

# 2) restore it into your data dir (it holds the pruned chain at the tip)
mkdir -p ./bloch-data
tar xzf bloch-db-snapshot-408482.tar.gz -C ./bloch-data   # → ./bloch-data/db

# 3) start — boots at the snapshot's tip, syncs the small remaining gap, mines
#    (make a miner address first: bloch-cli newwallet ~/miner-wallet.json)
./target/release/bloch --data-dir ./bloch-data \\
  --listen /ip4/0.0.0.0/tcp/16110 \\
  --peer /ip4/45.32.154.137/tcp/16110 \\
  --mine --miner-address bloch1q…YOUR_ADDRESS</code></pre>
    <div class="prose">
      <p>Confirm with <code>bloch-cli getblockcount</code> (it should already be near the network tip) and <code>bloch-cli getpeerinfo</code>. The snapshot <strong>excludes node identity</strong>, so your node generates its own — run as many as you like. Drop <code>--mine --miner-address</code> to run a pure relay/seed.</p>
      <p class="small">Snapshot published to the <a href="downloads.html">downloads host</a>. It is a periodic capture of a Postern-operated node's pruned state — one operator, not official infrastructure; verify it, or produce your own from any node you trust with <code>tar czf snap.tgz -C &lt;data-dir&gt; db</code>.</p>
    </div>
  </div>
</section>

<section aria-labelledby="edge-h">
  <div class="wrap">
    <p class="kicker" id="edge-h">Worked example · deploy on a VPS</p>
    <h2>Standing a node up on Edgevana (what actually worked).</h2>
    <div class="warnpanel" role="note">
      <h3>No affiliation — read this</h3>
      <p>Postern Labs has <strong>no association, partnership, sponsorship, or endorsement relationship with Edgevana</strong>. It is simply one host we happened to use successfully while testing; <strong>any routable VPS or bare-metal box works identically</strong>. Nothing here is a recommendation to buy from Edgevana or any provider.</p>
    </div>
    <div class="prose">
      <p>The model we ran — nothing special, a small routable Linux box:</p>
      <ul>
        <li><strong>Ubuntu 24.04 LTS</strong> · ~2 vCPU · ~8&nbsp;GB RAM · ~33&nbsp;GB disk</li>
        <li>A <strong>public, routable IPv4</strong> (so it can reach the bootstrap and be reached back) + SSH-key access</li>
      </ul>
      <p><strong>On GPUs, honestly:</strong> the PoW is SHAKE-256 hashcash + a Module-SIS gate, and the reference miner is <strong>CPU-bound</strong> — there is <strong>no GPU miner today</strong>, so a GPU instance buys you <em>nothing</em> for mining right now. A modest CPU box is the working recipe. (A SHAKE/lattice GPU or ASIC miner is buildable — see the <a href="asic.html">ASIC page</a> — but none exists yet.)</p>
    </div>
<pre><code># on the VPS (Ubuntu): deps + Rust, then build
sudo apt update && sudo apt install -y git clang cmake pkg-config build-essential curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y &amp;&amp; . "$HOME/.cargo/env"
git clone &lt;gitlab.com/blochsispow-group/BlochSISPoW-project&gt; bloch &amp;&amp; cd bloch
cargo build --release --bin bloch --bin bloch-cli

# restore the snapshot (above) into ./bloch-data — or skip it and sync
# from genesis — then run as a seed + miner
./target/release/bloch --data-dir ./bloch-data \\
  --listen /ip4/0.0.0.0/tcp/16110 --max-peers 500 \\
  --peer /ip4/45.32.154.137/tcp/16110 \\
  --mine --miner-address bloch1q…YOUR_ADDRESS</code></pre>
    <div class="prose">
      <p class="small">Keep <code>--max-peers 500</code> so it can act as a hub/seed for others. Confirm with <code>bloch-cli getpeerinfo</code> and <code>getblockcount</code>. The chain is <strong>unaudited</strong> and the coin is <strong>worthless by design</strong> — run it to strengthen the research network, not as an investment.</p>
    </div>
  </div>
</section>
`;

const ASIC_MINING = `
<section class="hero">
  <div class="wrap">
    <div class="rule" aria-hidden="true"></div>
    <p class="kicker">Custom mining hardware</p>
    <h1>Customizing an ASIC for Bloch-SIS-PoW.</h1>
    <p class="lede">What a custom miner (ASIC or FPGA) must accelerate to mine the Bloch-SIS proof-of-work — and how to build one. This is an engineering description of the algorithm, <strong>not</strong> an endorsement to build hardware.</p>
    <div class="warnpanel" role="note">
      <h3>Read first</h3>
      <ul>
        <li><strong>No economic reason to build one.</strong> The coin is <strong>not a security and not an asset</strong> — no price, no market, <strong>no value claim</strong>. Do this for research/education only.</li>
        <li><strong>Parameters are NOT security-validated.</strong> At <code>β = q/16</code> the residual gate is structurally weak by the protocol's own admission; the chain is <strong>unaudited</strong> and 51%-attackable, and the no-shortcut proof is outstanding. Any consensus parameter can change in a future hard fork and invalidate a fixed-parameter chip.</li>
      </ul>
    </div>
  </div>
</section>

<section aria-labelledby="pow-h">
  <div class="wrap">
    <p class="kicker" id="pow-h">The PoW</p>
    <h2>Two gates per candidate.</h2>
    <div class="prose">
      <p>A valid block carries a <strong>SIS witness</strong>: a short integer vector <code>s</code> that (1) satisfies a Module-SIS lattice gate and (2) whose block's auxiliary hash beats the difficulty target. Mining searches nonces/seeds for a candidate passing both.</p>
    </div>
<pre><code>(A, t) = SHAKE256-expand(seed)     # A ∈ Z_q^{m×n},  t ∈ Z_q^m
r = A·s - t   (mod q, centered)    # residual
gate_ok = ||r||∞ &lt; β   on k coefficients        # structural filter (Module-SIS)
work_ok = SHAKE256(header‖s) ≤ target           # cumulative hashcash work
valid   = gate_ok AND work_ok</code></pre>
    <div class="prose">
      <p>Security is <strong>cumulative SHAKE-256 hashcash work</strong>; the lattice gate is a <strong>structural filter</strong>, not a security claim by itself.</p>
    </div>
  </div>
</section>

<section aria-labelledby="param-h">
  <div class="wrap">
    <p class="kicker" id="param-h">Canonical parameters</p>
    <h2>Aligned with ML-DSA-65 on purpose.</h2>
    <dl>
      <div class="defrow"><dt><code>q = 8 380 417</code></dt><dd>= 2²³ − 2¹³ + 1 — the <strong>ML-DSA-65 / FIPS 204 (Dilithium) prime</strong>, chosen so an NTT core can be shared with the signature subsystem. That's the reuse hook: existing Dilithium/Kyber NTT + modular-reduction hardware IP drops straight in.</dd></div>
      <div class="defrow"><dt><code>n = 256</code>, <code>m = 512</code></dt><dd>Solution dimension and matrix rows (<code>A ∈ Z_q^{m×n}</code>, <code>m = 2n</code>).</dd></div>
      <div class="defrow"><dt><code>β = q/16</code></dt><dd>Residual ∞-norm bound. <strong>Not security-validated</strong> — weak by design at this value.</dd></div>
      <div class="defrow"><dt><code>k = 4…8</code></dt><dd>Residual coefficients the gate constrains — since node v0.1.0-alpha2 a <strong>difficulty-driven ramp</strong>: k=4 today, rising 5→6→7→8 as sustained network difficulty grows and easing back if it falls. Each step of k makes valid candidates ~8× rarer (~4096× from k=4 to k=8). A custom miner must handle the whole range, not a fixed k.</dd></div>
    </dl>
  </div>
</section>

<section aria-labelledby="acc-h">
  <div class="wrap">
    <p class="kicker" id="acc-h">What the chip accelerates</p>
    <h2>Keccak + 24-bit modular multiply.</h2>
    <div class="prose">
      <ol>
        <li><strong>SHAKE-256 / Keccak-f[1600]</strong> (throughput core) — expands <code>A</code> (≈131k field entries) and <code>t</code> from the seed, and computes the work hash. Standard SHA-3 permutation logic.</li>
        <li><strong>Matrix-vector product <code>A·s mod q</code></strong> — 512 dot-products of length 256 over a 24-bit prime. Reuse Dilithium NTT butterflies / a wide MAC array with centered reduction.</li>
        <li><strong>Norm gate</strong> — <code>k</code> parallel comparators against <code>β</code>; place it early to reject most candidates before the work hash.</li>
        <li><strong>Difficulty compare</strong> — 256-bit compare of the aux hash to the ASERT-tuned target (~30 s block time, ±4×/step).</li>
      </ol>
      <p>The design is <strong>compute-bound on Keccak + 24-bit modmul</strong> and can keep <code>A</code> on-die (≈384 KiB), which is what makes it ASIC-amenable rather than memory-hard.</p>
    </div>
    <div class="prose" style="margin-top:1rem">
      <p><strong><a href="/Bloch-ASIC-Customization-Spec.pdf">Full ASIC customization spec (PDF)&nbsp;↓</a></strong> — the pipeline diagram, the practical FPGA-first path, and the honest limits. Reference solver: <code>crates/bloch-sis-pow</code> in the protocol repo (see <a href="run-a-node.html">Run a node</a>). Unaudited; parameters not security-validated.</p>
    </div>
  </div>
</section>
`;

const ACKNOWLEDGMENTS = `
<section class="hero">
  <div class="wrap">
    <div class="rule" aria-hidden="true"></div>
    <p class="kicker">Acknowledgments &amp; homage</p>
    <h1>Standing on the shoulders of others — and saying so.</h1>
    <p class="lede">A homage, in the founder's own words — of the people, for the people: on liberty, privacy, and the guarantee of fundamental rights. And an honest record of the works and licenses Postern builds upon.</p>
  </div>
</section>

<section aria-labelledby="wethepeople-h">
  <div class="wrap">
    <p class="kicker">Homage · of the people, for the people</p>
    <h2 id="wethepeople-h">Nós, o Povo — We, the People</h2>
    <div class="prose">
      <p>Three words open the Constitution of the United States — <em>&ldquo;We, the People&rdquo;</em> — and with them something new entered the world: authority that flows not from a crown or a conqueror, but from a people binding itself, in writing, to rules it agrees to keep even when keeping them costs something. That is the oldest and deepest idea I build on: a promise made durable, a pre-commitment that outlives the mood of the moment.</p>
      <p>The <strong>Fifth Amendment</strong> is where that promise becomes a guarantee you can stand on: <em>&ldquo;No person shall &hellip; be deprived of life, liberty, or property, without due process of law; nor shall private property be taken for public use, without just compensation.&rdquo;</em> Read it slowly. The State is bound. Property is not held at the pleasure of power — it is secured by law, and by law that must follow process. From that security grew the freedom to contract and to enterprise, the freedom of atypical and innominate agreements, and, in our century, the freedom to write software and to issue tokens that no sovereign owns.</p>
      <p>And liberty is not only the freedom to act in the open; it is the security of a private sphere. The right of the people to be secure in their persons, houses, papers, and effects — the <strong>Fourth Amendment's</strong> guarantee against unreasonable search and seizure — is the quiet precondition of every other freedom: there is no free conscience, no free enterprise, and no honest contract without a space the State cannot enter without cause and without process. This is why I build Postern. Privacy is not a feature to be bolted on; it is a fundamental right, and the tools that protect it are, at their best, instruments of ordered liberty — the private sphere defended by mathematics, as the Constitution defends it by law.</p>
      <p>I do not treat these as abstractions. Constitutionalism, federalism, substantive due process of law, and the guarantees of life, liberty, and property are the load-bearing beams of the freer world we inherited. I honor the jurists who gave that order its voice — <strong>Oliver Wendell Holmes&nbsp;Jr.</strong> and <strong>Felix Frankfurter</strong> among them — and the long tradition of ordered liberty they served.</p>
      <p>This is also the thread of my own scholarship. In <em>The Cryptographic Constitution</em> I argue that a protocol can do, by mathematics, what a constitution does by law: secure cooperation through strict pre-commitment and repeated games — civil cooperation without a sovereign. The ownerless Bloch base is that idea made to run: rules that bind because no one can bend them, the way the Fifth Amendment binds because a people chose to be bound. What America wrote in law, we try to keep faith with in code.</p>
      <p>So Postern chooses its home, and says so plainly: <strong>Postern is and will be American</strong> — in its allegiance to these principles first, and in the ground it stands on. Not because it is fashionable, but because this is the constitutional order that made building at all possible, and gratitude should be spoken out loud.</p>
      <p>It is, in the end, a beautiful story — the one called the United States of America: a people who wrote down their promises and then, imperfectly and across centuries, kept trying to honor them. Of the people, for the people.</p>
      <p>God bless America. <em>Deus abençoe a América</em> — em profundo respeito, admiração e deferência à formação e à garantia dos direitos fundamentais da sociedade do século&nbsp;XXI.</p>
      <p class="dim">— T.T., founder</p>
    </div>

    <div class="prose">
      <p class="kicker" id="remissao-h">Remissão / References</p>
      <ul class="small">
        <li>Tiago Beltrão de Azevedo Tenório Acioli, &ldquo;The Cryptographic Constitution: Pre-Commitment, Repeated Games, and the Architecture of Civil Cooperation Without a Sovereign&rdquo; (SSRN, 2026) — <a href="https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6648959" rel="noopener">papers.ssrn.com/&hellip;abstract_id=6648959</a></li>
        <li>Tiago Beltrão de Azevedo Tenório Acioli, &ldquo;The Cryptographic Constitution, Volume&nbsp;III: Sarnoff, Metcalfe, Reed — The Three Eras of Network Cooperation and the Reconstruction of Civitas in the Twenty-First Century&rdquo; (SSRN, 2026) — <a href="https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6701940" rel="noopener">papers.ssrn.com/&hellip;abstract_id=6701940</a></li>
      </ul>
      <p class="small dim">This page is a personal homage and statement of allegiance, not legal advice. Postern products remain unaudited reference-prototypes; the BLCH coin is worthless by design and is not a security; the Bloch-SIS-PoW base is ownerless. None of the respect recorded here implies endorsement by any party named.</p>
    </div>
  </div>
</section>

<section aria-labelledby="homage-h">
  <div class="wrap">
    <p class="kicker" id="homage-h">A homage, in the founder's own words</p>
    <div class="prose">
      <p>I build Postern in profound respect, admiration, and deference to the American constitutional order, and to the institutions and people that made a freer world possible.</p>
      <p>If we live in a better world, America played an indispensable part in it. From <strong>federalism</strong> and <strong>constitutionalism</strong>; from <strong>substantive due process of law</strong>; from the guarantees of the rights to <strong>life, liberty, and property</strong>; from the freedom to enterprise, to self-determine, to contract — including the freedom of <strong>atypical and innominate contracts</strong> — and from the security of property rights, grew the very ground on which tokens, blockchains, and software evolve and make our days better. These are not abstractions to me. They are the load-bearing beams of the century we live in.</p>
      <p>I honor the jurists who gave that order its voice — <strong>Oliver Wendell Holmes&nbsp;Jr.</strong> and <strong>Felix Frankfurter</strong> among them — and the long tradition of ordered liberty they served.</p>
      <p>I record my deep gratitude to <strong>Google</strong>, whose open Android foundation lets anyone build, and to <strong>Anthropic</strong>, whose tools helped bring this work into being. Postern stands on the shoulders of others, and says so plainly.</p>
      <p>In homage to all of this, <strong>Postern is and will be American</strong> — in its allegiance to these principles, and in the home it chooses.</p>
      <p>God bless America. <em>Deus abençoe a América</em> — em profundo respeito, admiração e deferência à formação e à garantia dos direitos fundamentais da sociedade do século&nbsp;XXI.</p>
      <p class="dim">— T.T., founder</p>
    </div>

    <figure style="margin:2.2rem 0 0;text-align:center">
      <svg viewBox="0 0 150 104" width="132" height="92" role="img" aria-label="T.T. monogram, drawn as the Greek letter Pi — the two T-stems share one bar" fill="none" stroke="#c07f45" stroke-width="8" stroke-linecap="round" stroke-linejoin="round">
        <path d="M22 34 H128"/>
        <path d="M50 34 V84"/>
        <path d="M100 34 V84"/>
        <circle cx="75" cy="86" r="3.6" fill="#c07f45" stroke="none"/>
      </svg>
      <figcaption style="margin-top:.5rem;line-height:1.4">
        <span style="font-weight:700;letter-spacing:.06em">T.T.</span> <span class="dim">— Founder of Postern Labs</span><br>
        <span class="small dim">two T's, one shared bar — &pi;</span>
      </figcaption>
    </figure>
  </div>
</section>

<section aria-labelledby="respect-h">
  <div class="wrap">
    <p class="kicker" id="respect-h">With respect for the works &amp; licenses we build upon</p>
    <div class="prose">
      <p>Postern is a builder among builders. We use others' work under their terms, name them, and never pretend their work is ours:</p>
      <ul>
        <li><strong>Android Open Source Project (AOSP)</strong> — used under the <strong>Apache License 2.0</strong>; attribution and NOTICE preserved. Postern products that run on Android are apps on stock Android; they are <strong>never</strong> called &ldquo;Android,&rdquo; nor a fork of it, nor &ldquo;Postern OS.&rdquo;</li>
        <li><strong>Google Play &amp; Google Mobile Services (GMS)</strong> — Google Play Services are <strong>not</strong> redistributed by Postern; where a Google-enabled persona exists it is the user's own Google account and install, honestly labeled the <strong>less-private</strong> side (it phones home to Google — that is separation, not privacy). We do <strong>not</strong> circumvent SafetyNet / Play Integrity; we disclose attestation honestly instead. The &ldquo;Android&rdquo; and &ldquo;Google Play&rdquo; names appear only in <strong>nominative</strong> use to say what our software interoperates with, never to imply endorsement.</li>
        <li><strong>Anthropic</strong> — the Claude tooling used to build much of this. Where our apps talk to Anthropic, it is with the user's own key, and that path is labeled the least-private one.</li>
        <li><strong>The open-source ecosystem</strong> — the Rust, Nix, and web crates and tools we depend on, each under its own license, listed with the products that use them.</li>
      </ul>
      <p class="small">Everything here remains <strong>UNAUDITED, reference-prototype</strong> software; the coin is worthless by design and is not a security; the Bloch-SIS-PoW base is ownerless. None of the respect recorded above is a claim of endorsement by any party named.</p>
    </div>
  </div>
</section>
`;

const pages = [
  {
    file: "index.html",
    title: "Postern Labs — privacy & security products, sold the honest way",
    desc: "Owned privacy and security products (the BlackBerry model) built on an ownerless post-quantum commons. Public beta: unaudited products on a nascent, 51%-attackable mainnet beta.",
    active: "index.html",
    body: HOME,
  },
  {
    file: "postern-vs-bloch.html",
    title: "Postern & Bloch-SIS-PoW — two different things · Postern Labs",
    desc: "Postern Labs is a company that owns products. Bloch-SIS-PoW is an ownerless protocol with no owner, no foundation, no official site, and no token sale.",
    active: "postern-vs-bloch.html",
    body: VS,
  },
  {
    file: "products.html",
    title: "Products — the honest catalog · Postern Labs",
    desc: "The Postern suite with honest labels: built vs designed, reference prototypes, and an unaudited badge on everything.",
    active: "products.html",
    body: PRODUCTS,
  },
  {
    file: "downloads.html",
    title: "Downloads — get the beta · Postern Labs",
    desc: "How to run the Postern beta: self-contained web apps, the reproducible Nix-built OS, and the Tauri desktop app — all from source, all unaudited.",
    active: "downloads.html",
    body: DOWNLOADS,
  },
  {
    file: "migration.html",
    title: "SHA-256 migration \u00b7 network status \u00b7 Postern Labs",
    desc: "Why Bloch is migrating to SHA-256: ~95% of block bodies were pruned everywhere and a new node can no longer sync. Balances are intact and snapshotted; the new chain carries them over. Honest about the attack window before FFG finality lands.",
    active: "migration.html",
    body: MIGRATION,
  },
  {
    file: "run-a-node.html",
    title: "Run a mainnet-beta node · Postern Labs",
    desc: "Build and run a Bloch-SIS-PoW mainnet-beta node: clone, cargo build, run a relay or a solo miner, check it over RPC, and peer without privileged seeds. Unaudited, 51%-attackable mainnet beta — coins carry no value claim.",
    active: "run-a-node.html",
    body: RUN_A_NODE + NODE_CHAT_HTML,
    scripts: [NODE_CHAT_JS],
  },
  {
    file: "snapshot.html",
    title: "Sync your node from a snapshot · Postern Labs",
    desc: "A new node CANNOT sync from genesis: ~95% of block bodies were pruned everywhere and are unrecoverable. Bootstrapping from the published snapshot is the supported path — an honest trust-the-file tradeoff, disclosed. Honest trust-the-operator tradeoff, disclosed; unaudited; no value claim.",
    active: "snapshot.html",
    body: SNAPSHOT_SYNC,
  },
  {
    file: "asic.html",
    title: "Customizing an ASIC for Bloch-SIS-PoW · Postern Labs",
    desc: "What a custom miner (ASIC/FPGA) must accelerate to mine Bloch-SIS-PoW — SHAKE-256 + Module-SIS gate (q=8380417, n=256, m=512, β=q/16, difficulty-driven k=4…8) — with a full PDF spec. Unaudited; parameters not security-validated; the coin has no value claim.",
    active: "asic.html",
    body: ASIC_MINING,
  },
  {
    file: "releases.html",
    title: "Release notes: peering upgrade · Postern Labs",
    desc: "What changed so more nodes can join and mine Bloch-SIS-PoW: --max-peers (past the ~50-node wall), --dns-seed cold-start, and a mining-readiness/IBD-latch fix. Non-consensus, unaudited.",
    active: "releases.html",
    body: RELEASE_PEERING,
  },
  {
    file: "security.html",
    title: "Security & internal audits · Postern Labs",
    desc: "Postern runs continuous internal, AI-assisted adversarial code review across the Bloch protocol and the Postern products. Latest pass: ~49 findings (2 critical, 6 high) — all criticals/highs remediated in code + adversarially re-verified. Full technical reports are published only after fixes are deployed on the live network (responsible disclosure). Not a substitute for the contracted third-party audit; k=4 51%-attackable beta.",
    active: "security.html",
    body: SECURITY,
  },
  {
    file: "disclaimer.html",
    title: "Disclaimer & legal · Postern Labs",
    desc: "The full honest disclaimer: unaudited beta, mainnet beta (51%-attackable; difficulty-driven k-ramp — k=4 today, climbing toward k=8 as hashrate grows, easing back if it falls), not-a-security, the 17% founder premine, no warranty, permissive licenses.",
    active: "disclaimer.html",
    body: DISCLAIMER,
  },
  {
    file: "pool.html",
    title: "Mining & the reference pool · Postern Labs",
    desc: "Solo mining on the Bloch-SIS-PoW mainnet beta needs no pool; the optional reference pool only smooths variance. Unaudited, 51%-attackable mainnet beta — coins carry no value claim.",
    active: "run-a-node.html",
    body: POOL,
  },
  {
    file: "blochprotocol.html",
    title: "The blochprotocol.com domain · Postern Labs",
    desc: "For compliance and consistency with the ownerless protocol, Postern Labs does not and cannot maintain a site at blochprotocol.com — it is not the owner, representative, or holder of any prerogatives over Bloch-SIS-PoW.",
    active: "postern-vs-bloch.html",
    body: BLOCH_NOTICE,
  },
  {
    file: "acknowledgments.html",
    title: "Acknowledgments & homage · Postern Labs",
    desc: "The founder's homage — 'Nós, o Povo / We, the People': a feature essay on liberty, privacy, and the guarantee of fundamental rights (Fourth & Fifth Amendments, Holmes Jr., Frankfurter), with SSRN references to The Cryptographic Constitution; gratitude to Google and Anthropic, and an honest record of the works and licenses Postern builds upon. Signed T.T.",
    active: "acknowledgments.html",
    body: ACKNOWLEDGMENTS,
  },
];

for (const p of pages) {
  fs.writeFileSync(path.join(OUT, p.file), page(p));
  console.log("wrote", p.file);
}
