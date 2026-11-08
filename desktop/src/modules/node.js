// modules/node.js — Node: manage the bloch node process + live telemetry + logs.
// Fully wired to REAL Tauri commands: node_start / node_stop / node_status /
// rpc / rpc_tor (+ the node-log event stream).
(function () {
  "use strict";
  const P = window.Postern, UI = P.ui, api = P.api;

  // SHA-256 of the `bloch` release binary this app is packaged to pin
  // (POSTERN_NODE_SHA256, baked at build time). Shown read-only in the
  // "Get the node binary" helper so the user can verify the file they point at
  // (`shasum -a 256 <path>`). Informational — the actual enforcement is the
  // backend's verify_node_integrity, which reads the env/build pin, not this UI.
  const NODE_SHA256_PIN = "4e5aeccbd3dfc2b3b8de85460938fea8b80add584437db5ceb807805be9aef7b";

  // log buffer survives route changes
  const logBuf = [];
  const MAX_LINES = 2000;
  let logEl = null;

  api.listen("node-log", (e) => {
    const line = String(e.payload);
    logBuf.push(line);
    if (logBuf.length > MAX_LINES) logBuf.splice(0, logBuf.length - MAX_LINES);
    if (logEl && logEl.isConnected) appendLine(logEl, line);
  });

  function appendLine(el, line) {
    const span = document.createElement("span");
    if (line.startsWith("[preview]")) span.className = "log-preview";
    span.textContent = line + "\n";
    el.appendChild(span);
    while (el.childNodes.length > MAX_LINES) el.removeChild(el.firstChild);
    el.scrollTop = el.scrollHeight;
  }

  P.register({
    id: "node",
    title: "Node",
    desc: "Run and observe the bloch full node — process control, telemetry, logs. Mainnet-beta, zero value.",
    group: "Advanced · testnet (zero value)",
    order: 1,
    live: () => api.isReal("node_start"),
    icon: `<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="7" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.6"/><rect x="3" y="13" width="18" height="7" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.6"/><circle cx="7" cy="7.5" r="1" fill="currentColor"/><circle cx="7" cy="16.5" r="1" fill="currentColor"/></svg>`,

    render(root) {
      const s = P.state.settings;
      const liveNode = api.isReal("node_start");
      const liveTor = api.isReal("rpc_tor");
      root.innerHTML = `
        <div class="stack">
          <div class="callout callout-warn">
            <strong>Mainnet-beta · zero value · unaudited.</strong> This runs the canonical
            <strong>mainnet</strong> Bloch chain, but it is a <strong>pre-mainnet-beta,
            unaudited</strong> prototype — coins have <strong>no value</strong>, the chain may still
            be reset, and nothing here is money. A freshly-started node takes time to sync the
            whole chain from the peer before balances are trustworthy.
          </div>

          <section class="card">
            <div class="card-head"><h2>Connection</h2><div class="spacer"></div>
              <span class="badge badge-brass" id="cn-mode-badge"></span>
            </div>
            <p class="note">Where this wallet reads balances and broadcasts signed transactions.
              <strong>Your keys never leave this device</strong> — signing is always local
              (native / postern-vault); only reads and an <em>already-signed</em> transaction ever
              reach a node. Remote means trusting that node for balance display + broadcast.</p>
            <div class="actions">
              <label class="check"><input type="radio" name="cn-mode" id="cn-public"> Public node (quick)</label>
              <label class="check"><input type="radio" name="cn-mode" id="cn-local"> Your own node (sovereign)</label>
              <label class="check"><input type="radio" name="cn-mode" id="cn-custom"> Custom endpoint</label>
            </div>
            <div id="cn-custom-box" class="hidden" style="margin-top:8px">
              <label class="field"><span>Custom RPC endpoint (http(s)://host[:port])</span>
                <input id="cn-custom-url" class="mono" placeholder="https://my-node.example.org:8645"></label>
              <label class="check" style="margin-top:6px"><input type="checkbox" id="cn-custom-ok">
                I confirm I trust this node with my balance queries and signed transactions.</label>
            </div>
            <p class="result-line" id="cn-active" style="margin-top:8px"></p>
          </section>

          <div class="grid2">
            <section class="card">
              <div class="card-head"><h2>Node process</h2><div class="spacer"></div>
                ${liveNode ? UI.liveBadge("live · tauri") : UI.stubBadge("preview — simulated node")}
              </div>
              <div class="field-row">
                <label class="field"><span>Binary</span><input id="nd-binary" value="${UI.esc(s.binary)}" placeholder="~/Downloads/bloch"></label>
                <label class="field"><span>Data dir</span><input id="nd-datadir" value="${UI.esc(s.dataDir)}"></label>
                <label class="field"><span>RPC port</span><input id="nd-port" type="number" value="${P.sanePort(s.rpcPort) ?? 8645}"></label>
              </div>
              <div class="field-row">
                <label class="field" style="flex:1;min-width:280px"><span>Peer (bootstrap · /ip4/&lt;addr&gt;/tcp/&lt;port&gt;)</span>
                  <input id="nd-peer" class="mono" value="${UI.esc(s.peer || P.CANONICAL_PEER)}" placeholder="${UI.esc(P.CANONICAL_PEER)}"></label>
              </div>
              <p class="note">A fresh node needs at least one peer to sync — defaults to the canonical
                mainnet node. Clear it only if you know what you're doing (an isolated node never syncs).</p>
              <div class="actions">
                <label class="check"><input id="nd-mine" type="checkbox" ${s.mine ? "checked" : ""}> Mine (Module-SIS PoW)</label>
                <label class="check"><input id="nd-testnet" type="checkbox" ${s.testnet ? "checked" : ""}> Testnet (default: mainnet)</label>
              </div>
              <div class="actions">
                <button class="btn btn-primary" id="nd-start">▶ Start node</button>
                <button class="btn btn-danger" id="nd-stop" disabled>■ Stop</button>
                <span class="result-line muted" id="nd-pid"></span>
              </div>
              ${liveNode ? "" : `<p class="note">No Tauri backend detected (browser preview) — Start runs a clearly-labeled <em>simulated</em> node so every flow can be exercised.</p>`}
            </section>

            ${P.api.backendKind === "browser" ? `
            <section class="card">
              <div class="card-head"><h2>Which node are you connected to?</h2><div class="spacer"></div>
                ${UI.stubBadge("read-only")}
              </div>
              <p class="note">A browser cannot run a node — no peer-to-peer sockets, no chain storage, no mining.
              So this app does not run one and does not pretend to. Every chain read you see here comes from
              <strong>somebody else's node</strong>, and you should know whose.</p>
              <div class="kv"><span class="k">endpoint</span><span class="v mono">${UI.esc(P.rpcUrl())} <span class="muted">(same-origin proxy)</span></span></div>
              <div class="kv"><span class="k">upstream</span><span class="v mono">45.32.154.137 <span class="muted">— the canonical public node</span></span></div>
              <div class="kv"><span class="k">it can</span><span class="v">serve you a <strong>wrong or stale</strong> balance, height or UTXO set; <strong>drop</strong> a broadcast</span></div>
              <div class="kv"><span class="k">it cannot</span><span class="v"><strong>spend, or learn a key.</strong> Signing runs in the WASM core in this tab; only already-signed bytes are sent</span></div>
              <p class="note">This is a <strong>trust-for-convenience</strong> trade, and it is the normal one for a
              browser wallet — but it is a trade. To depend on nobody, run your own node and point the
              <strong>desktop app</strong> at <span class="mono">127.0.0.1</span>: same panes, same keys, no third party
              between you and the chain.</p>
            </section>` : ""}

            <section class="card">
              <div class="card-head"><h2>Telemetry</h2><div class="spacer"></div>
                <span class="mono muted" id="nd-rpcurl"></span>
              </div>
              <div class="stats">
                <div class="stat"><b id="nd-height">—</b><span>tip height</span></div>
                <div class="stat"><b id="nd-peers">—</b><span>peers</span></div>
                <div class="stat"><b id="nd-mempool">—</b><span>mempool</span></div>
                <div class="stat"><b id="nd-mining">—</b><span>mining</span></div>
              </div>
              <p class="result-line" id="nd-sync" style="margin-top:10px"></p>
              <p class="result-line muted" id="nd-rpcerr" style="margin-top:6px"></p>
            </section>
          </div>

          <section class="card">
            <div class="card-head"><h2>Get the node binary</h2><div class="spacer"></div>
              <span class="badge badge-brass">sovereign setup</span>
            </div>
            <p class="note">"Your own node" (sovereign mode) runs the <code>bloch</code> full node on this
              machine and points the wallet at <code>http://127.0.0.1:${P.sanePort(s.rpcPort) ?? 8645}</code>.
              It is an explicit opt-in — the wallet's default stays the remote public node.</p>
            <ol class="note" style="margin:8px 0 8px 18px; line-height:1.7">
              <li>Obtain the <code>bloch</code> binary — build it from the <code>bloch-blockchain</code>
                repo (<code>cargo build --release --bin bloch</code>) or use the copy at
                <code>~/Downloads/bloch</code>.</li>
              <li>Make it executable: <code>chmod +x ~/Downloads/bloch</code>.</li>
              <li>Set <strong>Binary</strong> above to that path (e.g. <code>~/Downloads/bloch</code>),
                keep <strong>Peer</strong> at the canonical mainnet node, leave <strong>Mine</strong> and
                <strong>Testnet</strong> off, then <strong>Start node</strong>.</li>
              <li>The node connects to the peer and reports the live mainnet tip; switch
                <strong>Connection</strong> to <em>Your own node</em> once your node has caught up.</li>
            </ol>
            <div class="callout callout-warn" style="margin-top:4px">
              <strong>Sync limitation (today).</strong> A brand-new node peers with mainnet and sees the
              tip, but it will <strong>not</strong> finish a full genesis sync on the current network:
              the canonical nodes are <strong>pruned</strong> (early block bodies are gone, so genesis
              IBD stalls) and fresh onboarding uses a signed chain <strong>snapshot</strong>, not
              genesis-up sync. Also, a node built from <code>bloch</code> HEAD activates the k=8 PoW
              soft-fork at height 40,320 and will reject the live k=4 chain's blocks ("invalid PoW")
              unless built to match the live activation height. Until snapshot onboarding is wired in,
              expect the local tip to sit near genesis — the wallet's default remote mode works fully
              meanwhile.
            </div>
            <label class="field"><span>SHA-256 of the shipped <code>bloch</code> (verify your file)</span>
              <input id="nd-sha" class="mono" readonly value="${UI.esc(NODE_SHA256_PIN)}"></label>
            <p class="note" style="margin-top:6px">To pin the node binary, launch the app with
              <code>POSTERN_NODE_SHA256=&lt;sha&gt;</code>: the backend then hashes the binary before
              spawning and refuses to start on a mismatch — <strong>tamper-evident, not hardware
              attestation</strong>. Without the env var the binary is name/location-checked but
              <strong>not</strong> hash-verified (the backend says so in the log). Use the SHA above for
              the shipped binary, or your own build's hash; verify any file with
              <code>shasum -a 256 ~/Downloads/bloch</code>.</p>
          </section>

          <section class="card">
            <div class="card-head"><h2>RPC over Tor</h2><div class="spacer"></div>
              ${liveTor ? UI.liveBadge("live · arti in-process") : UI.stubBadge("preview — simulated circuit")}
            </div>
            <p class="note">Query a remote node through an in-process Tor circuit (Arti) — the node never learns this machine's IP. First call bootstraps Tor (takes seconds), then circuits are reused.</p>
            <div class="actions">
              <label class="field" style="flex:1;min-width:240px"><span>Onion endpoint (&lt;addr&gt;.onion:port[/path] — backend rejects non-.onion hosts)</span>
                <input id="nd-torend" placeholder="abcdefgh…xyz.onion:8645" class="mono"></label>
              <button class="btn" id="nd-torgo" style="align-self:flex-end">Query getnetworkinfo</button>
            </div>
            <pre class="json-view" id="nd-torout" style="max-height:160px">—</pre>
          </section>

          <section class="card">
            <div class="card-head"><h2>Node log</h2><div class="spacer"></div>
              <button class="btn btn-ghost btn-sm" id="nd-clear">clear</button>
            </div>
            <pre class="logview" id="nd-log" style="height:280px"></pre>
          </section>

          ${UI.privacyCaveat()}
        </div>`;

      // hydrate log buffer
      logEl = UI.qs("#nd-log", root);
      logBuf.forEach((l) => appendLine(logEl, l));

      const setRunning = (on, pid) => {
        UI.qs("#nd-start", root).disabled = on;
        UI.qs("#nd-stop", root).disabled = !on;
        UI.qs("#nd-pid", root).textContent = on && pid ? `pid ${pid}` : "";
        UI.qs("#nd-mining", root).textContent = on ? (UI.qs("#nd-mine", root).checked ? "ON" : "OFF") : "—";
      };
      setRunning(P.state.node.running, P.state.node.pid);

      const syncSettings = () => {
        const rawPeer = UI.qs("#nd-peer", root).value.trim();
        // Keep a well-formed peer as-is; an empty field is allowed (isolated,
        // won't sync); anything else is rejected back to the canonical peer.
        const peer = rawPeer === "" ? "" : (P.sanePeer(rawPeer) ?? P.CANONICAL_PEER);
        if (rawPeer !== "" && P.sanePeer(rawPeer) === null) {
          UI.qs("#nd-peer", root).value = peer;
          UI.toast("Peer must be /ip4/<addr>/tcp/<port> — reset to the canonical node", "warn");
        }
        Object.assign(P.state.settings, {
          binary: UI.qs("#nd-binary", root).value,
          dataDir: UI.qs("#nd-datadir", root).value,
          rpcPort: P.sanePort(UI.qs("#nd-port", root).value) ?? 8645,
          peer,
          mine: UI.qs("#nd-mine", root).checked,
          testnet: UI.qs("#nd-testnet", root).checked,
        });
        P.saveSettings();
        UI.qs("#nd-rpcurl", root).textContent = P.rpcUrl();
      };
      ["nd-binary", "nd-datadir", "nd-port", "nd-peer", "nd-mine", "nd-testnet"].forEach((id) =>
        UI.qs("#" + id, root).addEventListener("change", () => { syncSettings(); refreshConn(); }));
      UI.qs("#nd-rpcurl", root).textContent = P.rpcUrl();

      // ── Connection mode (public / local / custom) ─────────────────────
      const custBox = UI.qs("#cn-custom-box", root);
      const refreshConn = () => {
        const cs = P.state.settings;
        UI.qs("#cn-public", root).checked = cs.rpcMode === "public";
        UI.qs("#cn-local", root).checked = cs.rpcMode === "local";
        UI.qs("#cn-custom", root).checked = cs.rpcMode === "custom";
        custBox.classList.toggle("hidden", cs.rpcMode !== "custom");
        UI.qs("#cn-mode-badge", root).textContent =
          cs.rpcMode === "local" ? "local · sovereign" : (P.rpcAllowCustom() ? "custom · remote" : "public · remote");
        UI.setResult(UI.qs("#cn-active", root), `active: ${P.rpcUrl()} — ${P.rpcTrustLabel()}`, "muted");
        UI.qs("#nd-rpcurl", root).textContent = P.rpcUrl();
      };
      UI.qs("#cn-custom-url", root).value = P.state.settings.rpcCustom || "";
      UI.qs("#cn-custom-ok", root).checked = !!P.state.settings.rpcCustomConfirmed;
      const setMode = (mode) => {
        P.state.settings.rpcMode = mode;
        P.saveSettings();
        refreshConn();
      };
      UI.qs("#cn-public", root).addEventListener("change", () => setMode("public"));
      UI.qs("#cn-local", root).addEventListener("change", () => setMode("local"));
      UI.qs("#cn-custom", root).addEventListener("change", () => setMode("custom"));
      const syncCustom = () => {
        const raw = UI.qs("#cn-custom-url", root).value.trim();
        const ok = UI.qs("#cn-custom-ok", root).checked;
        const valid = !!P.saneRpcUrl(raw);
        if (ok && !valid) {
          UI.qs("#cn-custom-ok", root).checked = false;
          UI.toast("Enter a valid http(s):// endpoint before confirming", "warn");
        }
        P.state.settings.rpcCustom = valid ? raw : "";
        P.state.settings.rpcCustomConfirmed = ok && valid;
        P.saveSettings();
        refreshConn();
      };
      UI.qs("#cn-custom-url", root).addEventListener("change", syncCustom);
      UI.qs("#cn-custom-ok", root).addEventListener("change", syncCustom);
      refreshConn();

      UI.qs("#nd-start", root).addEventListener("click", async () => {
        syncSettings();
        try {
          const pid = await api.invoke("node_start", {
            binary: P.state.settings.binary,
            dataDir: P.state.settings.dataDir,
            rpcPort: P.state.settings.rpcPort,
            peer: P.state.settings.peer,
            testnet: P.state.settings.testnet,
            mine: P.state.settings.mine,
          });
          setRunning(true, pid);
          UI.toast(liveNode ? `Node started (pid ${pid})` : `Simulated node started (preview)`, "ok");
        } catch (e) {
          UI.toast(`Start failed: ${e}`, "err", 5000);
        }
      });

      UI.qs("#nd-stop", root).addEventListener("click", async () => {
        try { await api.invoke("node_stop"); } catch (e) { UI.toast(`${e}`, "err"); }
        setRunning(false);
      });

      UI.qs("#nd-clear", root).addEventListener("click", () => {
        logBuf.length = 0;
        logEl.textContent = "";
      });

      UI.qs("#nd-torgo", root).addEventListener("click", async () => {
        const out = UI.qs("#nd-torout", root);
        const ep = UI.qs("#nd-torend", root).value.trim();
        if (!ep) { out.innerHTML = UI.emptyState("Enter an endpoint first."); return; }
        out.innerHTML = UI.loadingState("bootstrapping Tor circuit… (first call takes seconds)");
        P.setState({ tor: "bootstrapping" });
        try {
          const r = await api.invoke("rpc_tor", { endpoint: ep, method: "getnetworkinfo", params: [] });
          P.setState({ tor: "ready" });
          out.textContent = JSON.stringify(r, null, 2);
        } catch (e) {
          P.setState({ tor: "error" });
          out.innerHTML = UI.errorState(e);
        }
      });

      // reflect central polling into the readouts
      this._unsub = P.onState((st) => {
        if (!root.isConnected) return;
        setRunning(st.node.running, st.node.pid);
        UI.qs("#nd-height", root).textContent = UI.fmtNum(st.node.height);
        UI.qs("#nd-peers", root).textContent = UI.fmtNum(st.node.peers);
        UI.qs("#nd-mempool", root).textContent = UI.fmtNum(st.node.mempool);
        // Honest sync status from the LOCAL node's own getnetworkinfo:
        //   running + syncing   → catching up (height climbing toward the tip)
        //   running + !syncing  → caught up / at tip
        //   process up, no RPC  → still booting / RPC not yet reachable
        const syncEl = UI.qs("#nd-sync", root);
        if (syncEl) {
          if (!st.node.running) {
            UI.setResult(syncEl, "", "muted");
          } else if (!st.node.rpcOk) {
            UI.setResult(syncEl, "● node process up — RPC not reachable yet (still booting)", "muted");
          } else if (st.node.syncing) {
            UI.setResult(syncEl, `● syncing — tip height ${UI.fmtNum(st.node.height)}, ${UI.fmtNum(st.node.peers)} peer(s)`, "warn");
          } else {
            UI.setResult(syncEl, `● synced — at tip ${UI.fmtNum(st.node.height)}`, "ok");
          }
        }
        UI.qs("#nd-rpcerr", root).textContent = st.node.rpcOk ? "" : P.rpcReachHint();
      });
    },

    onHide() {
      if (this._unsub) { this._unsub(); this._unsub = null; }
      logEl = null;
    },
  });
})();
