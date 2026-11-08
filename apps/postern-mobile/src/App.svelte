<script>
  // Postern Mobile — shell (skeleton). This item is the framework/build
  // skeleton only: a self-contained, same-origin, CSP-strict Svelte + Vite PWA
  // shell. The trust-bearing screens (real keygen/import/sign/send) are wired in
  // sibling items on the REUSED WASM PQ core + wallet-live.js + /rpc — they are
  // shown here as clearly-labelled previews, never faked.
  import WALLET from './lib/wallet-core.js';

  const APP_BASE = '/apps/postern-mobile/';

  const tabs = [
    { id: 'balance', glyph: '◈', label: 'Balance' },
    { id: 'receive', glyph: '↓', label: 'Receive' },
    { id: 'send',    glyph: '↑', label: 'Send' },
    { id: 'approve', glyph: '✍', label: 'Approve' },
    { id: 'keys',    glyph: '🔑', label: 'Keys' },
  ];
  let active = 'balance';

  // Genuine wire to the REUSED pure core (no faked values): this is a live
  // computation, not a stubbed constant. It proves the shell can call the
  // extracted, host-tested Bloch helpers.
  const coreSelfCheck = {
    sha3_abc: WALLET.toHex(WALLET.sha3_256(WALLET.utf8('abc'))),
    rpc_body: WALLET.getbalanceRequest('blk1exampleaddressshapeonly'),
  };
</script>

<div class="phone">
  <header class="topbar">
    <div class="brand">
      <span class="dot" aria-hidden="true"></span>
      <span>Postern Mobile</span>
    </div>
    <span class="badge" title="Not a hardware keystore">software keystore</span>
  </header>

  <div class="honesty" role="note">
    <strong>Reference prototype — UNAUDITED.</strong>
    Software (browser) keystore, <em>not</em> the phone's Secure Enclave / StrongBox.
    Reads run over the hosted same-origin <span class="mono">/rpc</span> proxy; no live
    node required. The coin <span class="mono">BLCH</span> is worthless by design and is
    not a security. This shell moves <strong>no real funds</strong> — signing/sending are
    wired on the real WASM PQ core in sibling screens and appear here only as labelled
    previews.
  </div>

  <main class="screens">
    {#if active === 'balance'}
      <section class="card">
        <h2>Balance <span class="tag">preview</span></h2>
        <p class="dim">
          The live balance screen calls <span class="mono">getbalance</span> /
          <span class="mono">getutxos</span> against the same-origin
          <span class="mono">/rpc</span> proxy. This skeleton does not display a number
          until that read path is wired — it will never show a fabricated balance.
        </p>
      </section>
    {:else if active === 'receive'}
      <section class="card">
        <h2>Receive <span class="tag">preview</span></h2>
        <p class="dim">
          Shows this wallet's real Bloch address (from the WASM core) plus a manual
          position-by-position fallback. Address shape is illustrative until the key is
          created/imported.
        </p>
      </section>
    {:else if active === 'send'}
      <section class="card">
        <h2>Send <span class="tag">preview</span></h2>
        <p class="dim">
          Builds and signs a transfer with the hybrid post-quantum core
          (Falcon-1024 &#8214; ML-DSA-65), then broadcasts via
          <span class="mono">sendrawtransaction</span> over <span class="mono">/rpc</span>.
          No transaction is signed or sent from this skeleton.
        </p>
      </section>
    {:else if active === 'approve'}
      <section class="card">
        <h2>Approve <span class="tag">preview</span></h2>
        <p class="dim">
          WYSIWYS approval: fail-closed decode, consequence tier, human sentence and a
          6-hex confirmation fragment. Refuses to under-display (e.g. multi-output
          transfers) rather than sign something it cannot honestly show.
        </p>
      </section>
    {:else}
      <section class="card">
        <h2>Keys <span class="tag">preview</span></h2>
        <p class="dim">
          Encrypted software keystore (Argon2id + XChaCha20-Poly1305 in IndexedDB) via
          <span class="mono">wallet-live.js</span>. The seed/key is never stored in
          plaintext, but decrypted material is briefly in browser memory while signing.
        </p>
      </section>
    {/if}

    <section class="card core">
      <h3>Core self-check <span class="tag ok">live</span></h3>
      <p class="dim small">
        Real output of the reused, host-tested Bloch core running in this tab — not a
        stubbed constant:
      </p>
      <dl class="kv">
        <dt>SHA3-256("abc")</dt>
        <dd class="mono small">{coreSelfCheck.sha3_abc}</dd>
        <dt>getbalance body</dt>
        <dd class="mono small">{coreSelfCheck.rpc_body}</dd>
      </dl>
    </section>
  </main>

  <nav class="tabbar" aria-label="Wallet sections">
    {#each tabs as t}
      <button
        class="tab"
        class:active={active === t.id}
        aria-current={active === t.id ? 'page' : undefined}
        on:click={() => (active = t.id)}
      >
        <span class="glyph" aria-hidden="true">{t.glyph}</span>
        {t.label}
      </button>
    {/each}
  </nav>

  <footer class="foot">
    <span class="mono small">{APP_BASE}</span>
    <span class="small muted">Postern Labs · self-contained same-origin PWA shell</span>
  </footer>
</div>

<style>
  .phone {
    max-width: 480px;
    margin: 0 auto;
    min-height: 100dvh;
    display: flex;
    flex-direction: column;
    padding: env(safe-area-inset-top) 0 0;
  }
  .topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 16px;
    border-bottom: 1px solid var(--line);
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 8px;
    font-weight: 600;
    letter-spacing: 0.2px;
  }
  .dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: radial-gradient(circle at 35% 30%, #7ec0ff, var(--accent));
  }
  .badge {
    font-size: 11px;
    color: var(--warn);
    border: 1px solid color-mix(in srgb, var(--warn) 40%, transparent);
    border-radius: 999px;
    padding: 3px 9px;
  }
  .honesty {
    margin: 12px 16px 4px;
    padding: 12px 14px;
    background: var(--panel);
    border: 1px solid var(--line);
    border-left: 3px solid var(--warn);
    border-radius: 10px;
    font-size: 13px;
    color: var(--dim);
  }
  .honesty strong { color: var(--ink); }
  .screens {
    flex: 1;
    padding: 8px 16px 16px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .card {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 16px;
  }
  .card h2, .card h3 { margin: 0 0 8px; }
  .card h2 { font-size: 18px; }
  .card h3 { font-size: 15px; }
  .card.core { background: var(--panel-2); }
  .dim { color: var(--dim); margin: 0; }
  .small { font-size: 12px; }
  .muted { color: var(--muted); }
  .tag {
    font-size: 11px;
    vertical-align: middle;
    color: var(--muted);
    border: 1px solid var(--line);
    border-radius: 6px;
    padding: 1px 6px;
    margin-left: 6px;
  }
  .tag.ok { color: var(--ok); border-color: color-mix(in srgb, var(--ok) 40%, transparent); }
  .kv { display: grid; grid-template-columns: 1fr; gap: 4px 0; margin: 8px 0 0; }
  .kv dt { color: var(--muted); font-size: 12px; margin-top: 6px; }
  .kv dd { margin: 0; word-break: break-all; color: var(--ink); }
  .tabbar {
    position: sticky;
    bottom: 0;
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    background: color-mix(in srgb, var(--bg) 85%, transparent);
    backdrop-filter: blur(8px);
    border-top: 1px solid var(--line);
  }
  .tab {
    appearance: none;
    background: none;
    border: 0;
    color: var(--dim);
    font: inherit;
    font-size: 11px;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 3px;
    padding: 10px 4px calc(10px + env(safe-area-inset-bottom));
    cursor: pointer;
  }
  .tab .glyph { font-size: 18px; line-height: 1; }
  .tab.active { color: var(--accent); }
  .foot {
    display: flex;
    flex-direction: column;
    gap: 2px;
    align-items: center;
    padding: 10px 16px 16px;
    text-align: center;
  }
</style>
