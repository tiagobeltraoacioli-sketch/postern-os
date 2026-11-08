// modules/messenger.js — Vestnik: the tier-honest Matrix messenger pane.
//
// HONESTY — capability-gated, never assumed:
//   * The matrix client exists in the desktop backend ONLY behind the opt-in
//     `vestnik-matrix` cargo feature. The vestnik_* client commands
//     (vestnik_matrix_status/login/session_seal/restore/sync_once/rooms/
//     send/logout) are ALWAYS registered, so registration alone proves
//     nothing: this pane gates every live claim on the backend's REAL
//     capability answer — vestnik_matrix_status.built — the same pattern as
//     the vault pane's keychain available:false. A no-feature build returns
//     the clean 'not built with matrix support (rebuild with --features
//     vestnik-matrix)' error and built:false, and this pane keeps the honest
//     disabled preview.
//   * In a vestnik-matrix build, a homeserver is contacted ONLY when the
//     user acts (Log in / Sync / Send) — never at startup: this pane invokes
//     only the local-state vestnik_matrix_status on render, never a
//     network-touching command.
//   * What is ALSO real (any backend build): the vestnik_* CUSTODY commands
//     (desktop/src-tauri/src/vestnik.rs) — the courier recipient secret
//     lives as the reserved vault entry 'vestnik/session-recipient'
//     (requires an UNLOCKED vault, fails closed when locked) and the sealed
//     SavedSession blob is stored/loaded/opened by the backend.
//   * The SecurityTier badges and the three bridged-disclosure strings below
//     BYTE-MATCH the Rust constants in crates/postern-messenger/src/lib.rs
//     (SecurityTier::badge(), disclosure::BRIDGE_TAB_BANNER /
//     BRIDGED_CONVERSATION_HEADER / BRIDGED_COMPOSE_NOTE).
//     messenger.test.mjs pins them byte-for-byte so no UI layer can soften
//     the wording — never edit them here alone.
(function () {
  "use strict";
  const P = window.Postern, UI = P.ui, api = P.api;

  // ── strings pinned byte-identical to crates/postern-messenger/src/lib.rs ──
  // (machine-checked by messenger.test.mjs; do not paraphrase, do not
  // "improve" — the Rust crate is the single source of truth.)
  const TIER_BADGE_INTERNAL = "E2EE (Postern)"; // SecurityTier::InternalE2ee.badge()
  const TIER_BADGE_BRIDGED = "⚠ Bridged — not E2EE"; // SecurityTier::BridgedExternal.badge()
  const BRIDGE_TAB_BANNER = "⚠ External bridge — these messages are NOT protected like your Postern chats. Anything you send or receive here leaves Postern's end-to-end encryption: your bridge server and the external service (e.g. Telegram) can read it in plaintext. The external service also sees the metadata — that this conversation exists, when you talk, and who talks to whom. Postern does not operate this bridge and cannot protect these messages.";
  const BRIDGED_CONVERSATION_HEADER = "⚠ Bridged conversation — not end-to-end encrypted. The bridge and the external service (e.g. Telegram) can read every message here, and the external service sees when and with whom you talk.";
  const BRIDGED_COMPOSE_NOTE = "⚠ Not E2EE — readable by the bridge and the external service.";

  const PREVIEW_NOTE = "preview — not built with matrix support (rebuild with --features vestnik-matrix)";

  // Sample rooms — ILLUSTRATIVE ONLY, rendered only in a NOT-BUILT build
  // where no real room list can exist; these rows exist to show the tier
  // wall (badges + mandatory bridged disclosure), nothing else.
  const SAMPLE_ROOMS = [
    { name: "#postern-dev (sample)", tier: "internal" },
    { name: "#design (sample)", tier: "internal" },
    { name: "Telegram: family group — via bridge (sample)", tier: "bridged" },
  ];

  // The backend's REAL capability answer (vestnik_matrix_status), refreshed
  // on every render. Until a backend says otherwise, honesty demands the
  // most conservative state: not built, not logged in.
  let matrixStatus = { built: false, logged_in: false };

  P.register({
    id: "messenger",
    title: "Vestnik",
    desc: "Matrix messenger — tier-honest E2EE/bridged wall + vault-custodied sealed session.",
    group: "Transmit",
    order: 2,
    // Live ONLY when the backend truly runs a matrix-capable build: the
    // commands are always registered (a no-feature build returns a clean
    // not-built error), so isReal alone would overclaim — the render()
    // below refreshes matrixStatus from vestnik_matrix_status and the badge
    // follows the backend's own built flag.
    live: () => api.isReal("vestnik_matrix_status") && matrixStatus.built === true,
    icon: `<svg viewBox="0 0 24 24"><path d="M4 5h16v11H8l-4 4z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M8 9.5h8M8 12.5h5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,

    async render(root) {
      // Custody commands (vestnik.rs) are live in ANY backend build.
      const custodyReal = api.isReal("vestnik_recipient_init");

      // Capability probe — LOCAL state only, never a homeserver contact
      // (vestnik_matrix_status reads the managed state; homeserver contact
      // happens only on the explicit user actions below).
      matrixStatus = { built: false, logged_in: false };
      if (api.isReal("vestnik_matrix_status")) {
        try {
          const s = await api.invoke("vestnik_matrix_status");
          if (s && s.built === true) matrixStatus = s;
        } catch (e) {
          // An erroring backend must read as not-built, never as live.
          matrixStatus = { built: false, logged_in: false };
        }
      }
      const built = matrixStatus.built === true;
      const loggedIn = built && matrixStatus.logged_in === true;

      // Real rooms exist only in a built + logged-in client, and only from
      // local sync state (vestnik_rooms makes no network call).
      let rooms = null;
      if (loggedIn) {
        try {
          const r = await api.invoke("vestnik_rooms");
          rooms = r.rooms || [];
        } catch (e) {
          rooms = null; // render the honest error state below
        }
      }

      const roomRow = (r) => `
        <div class="kv-row">
          <span class="k">${UI.esc(r.name || r.room_id || "(unnamed room)")}</span>
          <span class="v">${r.tier === "internal"
            ? `<span class="badge">${TIER_BADGE_INTERNAL}</span>`
            : `<span class="badge badge-stub">${TIER_BADGE_BRIDGED}</span>`}</span>
        </div>`;

      const internalRooms = (rooms || (built ? [] : SAMPLE_ROOMS)).filter((r) => r.tier === "internal");
      const bridgedRooms = (rooms || (built ? [] : SAMPLE_ROOMS)).filter((r) => r.tier !== "internal");

      // Compose is enabled ONLY for internal-tier rooms in a built,
      // logged-in client. Bridged rooms NEVER get a compose surface.
      const composeEnabled = loggedIn && internalRooms.length > 0;

      root.innerHTML = `
        <div class="stack">
          <div class="grid2" style="grid-template-columns: minmax(0,1.6fr) minmax(0,1fr)">
            <div class="stack">
              <section class="card" id="vk-login">
                <div class="card-head"><h2>Account</h2><div class="spacer"></div>
                  ${built
                    ? UI.liveBadge(loggedIn ? "live — logged in" : "live — vestnik-matrix build")
                    : UI.stubBadge(PREVIEW_NOTE)}
                </div>
                ${built ? `
                <p class="note">This is a <span class="mono">vestnik-matrix</span> build: the matrix
                  client runs in the desktop backend, and a homeserver is contacted <strong>only when
                  you act</strong> (Log in / Sync / Send) — never at startup. The homeserver you log
                  into sees the social graph (rooms, timestamps, who talks to whom); there is no Tor
                  wiring on this path. The store passphrase encrypts the SDK's sqlite store at the
                  SDK layer only — it is not PQ-vault-wrapped.</p>` : `
                <p class="note">This build was made without the <span class="mono">vestnik-matrix</span>
                  cargo feature, so the desktop backend does not carry the matrix client — no login,
                  no sync, no homeserver contact is possible here. The matrix client runs only in a
                  vestnik-matrix build, only on user action. These fields stay disabled; nothing here
                  connects anywhere.</p>`}
                <div class="actions" style="margin-top:8px">
                  <input class="input" id="vk-hs" style="flex:1" placeholder="homeserver URL — e.g. matrix.example${built ? "" : " (disabled: not a vestnik-matrix build)"}" ${built ? "" : "disabled"}>
                </div>
                <div class="actions">
                  <input class="input" id="vk-user" style="flex:1" placeholder="username — e.g. vestnik${built ? "" : " (disabled: not a vestnik-matrix build)"}" ${built ? "" : "disabled"}>
                  <input class="input" id="vk-pass" type="password" style="flex:1" placeholder="password" ${built ? "" : "disabled"}>
                </div>
                <div class="actions">
                  <input class="input" id="vk-storepass" type="password" style="flex:1" placeholder="store passphrase (SDK-layer sqlite encryption — not PQ-vault-wrapped)" ${built ? "" : "disabled"}>
                  <button class="btn btn-primary" id="vk-loginbtn" ${built && !loggedIn ? "" : "disabled"} title="${UI.esc(built ? "Contacts the homeserver — a user action" : PREVIEW_NOTE)}">Log in</button>
                  <button class="btn" id="vk-sync" ${loggedIn ? "" : "disabled"} title="Contacts the homeserver — a user action">Sync</button>
                  <button class="btn" id="vk-logout" ${loggedIn ? "" : "disabled"} title="Local drop only — the homeserver-side token is NOT invalidated">Log out</button>
                </div>
              </section>

              <section class="card" id="vk-internal">
                <div class="card-head"><h2>Conversations — Postern internal</h2><div class="spacer"></div>
                  <span class="badge">${TIER_BADGE_INTERNAL}</span>
                </div>
                ${built
                  ? (loggedIn
                    ? (rooms === null
                      ? UI.errorState("room list unavailable — try Sync")
                      : (internalRooms.length
                        ? `<div class="kv" style="margin-top:8px">${internalRooms.map(roomRow).join("")}</div>`
                        : UI.emptyState("No internal-tier rooms yet", "Sync first — rooms appear from local sync state, and only provably E2EE rooms are classified internal (fail-closed).")))
                    : UI.emptyState("Not logged in", "Log in above (a user action — that is when the homeserver is first contacted), then Sync."))
                  : `<p class="note">Sample rooms — illustrative only (no room list exists without the
                    matrix client). The tier wall is the point: anything not provably internal E2EE
                    is classified bridged, fail-closed, never silently downgraded.</p>
                  <div class="kv" style="margin-top:8px">${internalRooms.map(roomRow).join("")}</div>`}
                <div class="actions" style="margin-top:12px">
                  ${composeEnabled ? `
                  <select class="input" id="vk-room" style="max-width:40%">
                    ${internalRooms.map((r) => `<option value="${UI.esc(r.room_id)}">${UI.esc(r.name || r.room_id)}</option>`).join("")}
                  </select>` : ""}
                  <input class="input" id="vk-compose" style="flex:1" placeholder="Compose — internal tier only${composeEnabled ? "" : (built ? " (log in and sync first)" : " (disabled: not a vestnik-matrix build)")}" ${composeEnabled ? "" : "disabled"}>
                  <button class="btn btn-primary" id="vk-send" ${composeEnabled ? "" : "disabled"} title="${UI.esc(composeEnabled ? "Contacts the homeserver — a user action" : (built ? "log in and sync first" : PREVIEW_NOTE))}">Send</button>
                </div>
                <p class="note">Compose is gated to the internal tier — the send path refuses any
                  room not classified E2EE-internal (no silent downgrade; the backend surfaces the
                  refusal verbatim), and bridged rooms get no compose surface at all.</p>
              </section>

              <section class="card" id="vk-bridged">
                <div class="card-head"><h2>Bridges — external</h2><div class="spacer"></div>
                  <span class="badge badge-stub">${TIER_BADGE_BRIDGED}</span>
                </div>
                <div class="callout" style="margin-top:8px">${BRIDGE_TAB_BANNER}</div>
                <div class="kv" style="margin-top:8px">
                  ${bridgedRooms.map(roomRow).join("")}
                </div>
                <div class="callout" style="margin-top:8px">${BRIDGED_CONVERSATION_HEADER}</div>
                <p class="note" style="margin-top:8px">${BRIDGED_COMPOSE_NOTE}</p>
                <p class="note">There is no compose box on this tier: composing into a bridged
                  conversation arrives only with the explicit, disclosed Bridges flow —
                  never as a fallback.</p>
              </section>
            </div>

            <div class="stack">
              <section class="card" id="vk-custody">
                <div class="card-head"><h2>Sealed session custody</h2><div class="spacer"></div>
                  ${custodyReal ? UI.liveBadge("live — vault custody") : UI.stubBadge("preview — custody needs the desktop backend")}
                </div>
                <p class="note">The courier recipient secret that opens the sealed
                  <span class="mono">SavedSession</span> blob is custodied as the reserved vault
                  entry <span class="mono">vestnik/session-recipient</span> — it requires an
                  <strong>unlocked</strong> vault and fails closed when locked. The sealed blob is
                  stored under the app data dir as opaque bytes. Sealing uses only the persisted
                  non-secret public half; restoring opens the blob with the vault-custodied secret.
                  No preview engine exists for custody or the client: faking either would be an
                  overclaim.</p>
                <div class="actions" style="margin-top:8px">
                  <button class="btn" id="vk-init" ${custodyReal ? "" : "disabled"}>Init session recipient (vault)</button>
                  <button class="btn" id="vk-open" ${custodyReal ? "" : "disabled"}>Open stored session</button>
                </div>
                <div class="actions">
                  <button class="btn" id="vk-seal" ${loggedIn ? "" : "disabled"} title="${UI.esc(loggedIn ? "Seal the live session to the custodied recipient (no homeserver contact)" : (built ? "log in first" : PREVIEW_NOTE))}">Seal live session</button>
                  <button class="btn" id="vk-restore" ${built ? "" : "disabled"} title="${UI.esc(built ? "Open the stored blob with the vault-custodied secret and restore the client (local only — no homeserver contact)" : PREVIEW_NOTE)}">Restore from sealed blob</button>
                </div>
                <div class="kv" style="margin-top:8px">
                  <div class="kv-row"><span class="k">recipient fp</span><span class="v mono" id="vk-fp">—</span></div>
                  <div class="kv-row"><span class="k">stored session</span><span class="v mono" id="vk-session">—</span></div>
                </div>
              </section>

              <div class="callout">
                <strong>Honest limits.</strong>
                <ul>
                  <li><strong>UNAUDITED</strong> pre-release, like everything in this repo.</li>
                  <li>Megolm is <strong>classical</strong> (Curve25519) — not post-quantum. Harvest-now-decrypt-later applies to intercepted transport ciphertext.</li>
                  <li>A homeserver sees the <strong>social graph</strong> (rooms, timestamps, who talks to whom) — no Tor wiring on this path. Mitigate with a self-hosted homeserver over Tor and no phone-number identity.</li>
                  <li>Sealed-at-rest covers the <strong>SavedSession blob only</strong> — not the SDK's sqlite store passphrase (SDK-layer encryption, not PQ-vault-wrapped), not the transport. Whoever opens the vault can open the blob and act as that Matrix device.</li>
                  <li>The desktop runs the matrix client <strong>only in a vestnik-matrix build, only on user action</strong> — never in CI, never at startup${built ? "" : "; this build does not carry it"}.</li>
                </ul>
              </div>
            </div>
          </div>

          ${UI.privacyCaveat()}
        </div>`;

      const rerender = () => this.render(root);

      // ── custody wiring (live in any backend build) ───────────────────────
      UI.qs("#vk-init", root).addEventListener("click", async () => {
        if (!custodyReal) return;
        try {
          const r = await api.invoke("vestnik_recipient_init");
          UI.qs("#vk-fp", root).textContent = r.fingerprint;
          UI.toast("Session recipient custodied in the vault", "ok");
        } catch (e) {
          UI.toast(String(e), "err");
        }
      });

      UI.qs("#vk-open", root).addEventListener("click", async () => {
        if (!custodyReal) return;
        try {
          const r = await api.invoke("vestnik_session_open");
          // Show WHO the session is — never render the bearer access token.
          const s = r.session || {};
          UI.qs("#vk-session", root).textContent =
            `${s.user_id || "?"} · ${s.device_id || "?"} (token withheld from display)`;
          UI.toast("Sealed session opened with the vault-custodied secret", "ok");
        } catch (e) {
          UI.toast(String(e), "err");
        }
      });

      // ── matrix client wiring (only reachable when built — every network
      //    touch below is an explicit user action) ──────────────────────────
      UI.qs("#vk-loginbtn", root).addEventListener("click", async () => {
        if (!built) return;
        try {
          const r = await api.invoke("vestnik_login", {
            homeserver: UI.qs("#vk-hs", root).value.trim(),
            username: UI.qs("#vk-user", root).value.trim(),
            password: UI.qs("#vk-pass", root).value,
            storePassphrase: UI.qs("#vk-storepass", root).value,
          });
          UI.toast(`Logged in as ${r.user_id || "?"} (${r.device_id || "?"})`, "ok");
          await rerender();
        } catch (e) {
          UI.toast(String(e), "err");
        }
      });

      UI.qs("#vk-sync", root).addEventListener("click", async () => {
        if (!built) return;
        try {
          await api.invoke("vestnik_sync_once");
          UI.toast("Synced once", "ok");
          await rerender();
        } catch (e) {
          UI.toast(String(e), "err");
        }
      });

      UI.qs("#vk-logout", root).addEventListener("click", async () => {
        if (!built) return;
        try {
          const r = await api.invoke("vestnik_logout");
          UI.toast(r.note || "Logged out locally", "ok");
          await rerender();
        } catch (e) {
          UI.toast(String(e), "err");
        }
      });

      UI.qs("#vk-send", root).addEventListener("click", async () => {
        if (!composeEnabled) return;
        try {
          const roomSel = UI.qs("#vk-room", root);
          const r = await api.invoke("vestnik_send", {
            roomId: roomSel ? roomSel.value : "",
            body: UI.qs("#vk-compose", root).value,
          });
          UI.qs("#vk-compose", root).value = "";
          UI.toast(`Sent (event ${String(r.event_id || "").slice(0, 18)}…)`, "ok");
        } catch (e) {
          // Includes the backend's VERBATIM tier refusal — never softened.
          UI.toast(String(e), "err");
        }
      });

      UI.qs("#vk-seal", root).addEventListener("click", async () => {
        if (!built) return;
        try {
          const r = await api.invoke("vestnik_session_seal");
          UI.qs("#vk-fp", root).textContent = r.fingerprint || "—";
          UI.toast(`Live session sealed + stored (${r.bytes} bytes)`, "ok");
        } catch (e) {
          UI.toast(String(e), "err");
        }
      });

      UI.qs("#vk-restore", root).addEventListener("click", async () => {
        if (!built) return;
        try {
          const r = await api.invoke("vestnik_restore", {
            homeserver: UI.qs("#vk-hs", root).value.trim(),
            storePassphrase: UI.qs("#vk-storepass", root).value,
          });
          UI.toast(`Restored ${r.user_id || "?"} — ${r.note || "local only"}`, "ok");
          await rerender();
        } catch (e) {
          UI.toast(String(e), "err");
        }
      });
    },
  });
})();
