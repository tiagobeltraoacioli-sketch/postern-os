# App review — Enterprise, Store & Voice/Markets UI

Reviewer: fable5 security + technology review, Postern Labs
Scope: `apps/postern-enterprise` (Consiglio), `apps/postern-store`, `apps/sotto`, `apps/vedetta`
Status: **PRE-RELEASE / UNAUDITED.** Read-only review; no code was modified.
Method: every source line of all four single-file apps read in full.

Findings are ranked most-severe first. Each: severity · file:line · concrete failure (inputs → bad outcome) · fix.

Bottom line up front: the four apps are unusually clean. The authz core in Consiglio (Chinese Wall, RBAC/ABAC, dual-control escrow) is correct as written; the three self-contained UIs escape output, pin CSP to disclosed hosts, and carry no covert telemetry. The one concrete defect worth acting on is the **plaintext Anthropic API key at rest in Consiglio** — the item the prior review flagged. Everything below it is low-severity or disclosed-limitation.

---

## 1. MEDIUM · Consiglio stores the Anthropic API key in PLAINTEXT localStorage (the flagged item)

**File:** `apps/postern-enterprise/index.html:973` (`LS.KEY = "consiglio.apikey"`), written at **:1627** and **:1625**, read at **:1631**.

```
973   const LS = { STATE: "consiglio.state", KEY: "consiglio.apikey", MODEL: ..., THEME: ... };
1625  $("#apiKey").value = store.get(LS.KEY, "");
1627  $("#apiKey").addEventListener("change", () => store.set(LS.KEY, $("#apiKey").value.trim()));
```

**Failure (inputs → bad outcome):** An admin pastes their `sk-ant-…` key into the policy-assistant field. Consiglio writes it verbatim to `localStorage["consiglio.apikey"]`. Any other script that runs in this origin, any browser-profile reader, any device-backup sync, or anyone with filesystem access to the profile reads the live key in the clear and can bill the admin's Anthropic account. This is the enterprise console — the one app of the four whose operator is an org admin of record — yet it is the **only** one of the four with no at-rest protection for the key.

**Why it stands out:** the other three apps in this slice (`sotto`, `postern-store`, `vedetta`) already ship a proven `KeySeal` module — PBKDF2-SHA-256 (310k it.) → non-extractable AES-256-GCM, fresh IV per write, AAD-bound, plaintext dropped from disk on lock. Consiglio has **no `KeySeal` at all**. Note this is *only* the assistant's Anthropic key: the admin and officer signing/ECDH keys are correctly sealed with `sealBlob`/`openBlob` (`:778`, `:1030`, `:1019`), so the crypto-governance keys are fine — the gap is exclusively the LLM key.

**Minimal sealing fix — SMALL/safe (apply now):** Port the existing `KeySeal` IIFE verbatim from `apps/sotto/index.html:709-773` (or the identical block in `postern-store`/`vedetta`), change its `AAD` constant to `"consiglio.apikey.v1"` and `LS.SEALED` to `"consiglio.apikey.sealed"`, then route the key through `getKey()/setKey()` exactly as sotto does (`sotto` :1133-1140), and add the same "lock key / unlock / remove lock" passphrase row to the Settings-&-assistant card (`:623-632`). The construction is already audited-in-pattern and copy-identical across three sibling apps, so risk is low; it is new-to-this-file code (~55 lines + one settings row), so exercise the lock/unlock/erase path once before shipping. Until sealed, the honest interim mitigation already true elsewhere applies: the Settings copy should state plainly that the key "sits readable in this browser's localStorage" (Consiglio currently only says "stored only in this browser", `:624` — weaker than the sibling apps' disclosure).

---

## 2. LOW / DISCLOSED · Consiglio audit chain is tamper-*evident* only against naive edits, not a determined local attacker

**File:** `apps/postern-enterprise/index.html:897-913` (`auditAppend`/`auditVerify`), verify button `:1560`.

**Failure:** `hash = SHA-256(entry ‖ prev-hash)` with the whole chain in `localStorage["consiglio.state"]`. An attacker who can edit localStorage can rewrite any entry and then recompute every subsequent hash (the algorithm is public and deterministic, `stableStringify` is in the same file), producing a chain that passes `auditVerify` cleanly. "Verify the chain" only catches a single edited row that wasn't re-hashed — not a full re-forge.

**Assessment:** This is **honestly disclosed** and not a code defect for the demo. The UI states the real protection lives outside this file: "the chain head is countersigned by the compliance officer and replicated outside IT's custody" (`:582-584`) and the honesty dialog repeats it (`:690`). The client-side chain is explicitly labeled advisory. **No fix required for the prototype**; the note here is to ensure the countersignature + off-IT replication is not lost when the product build lands. **LARGE/defer (human)** — it is a product-architecture guarantee, not a page edit.

---

## 3. LOW · Vedetta "Custom endpoint" provider is blocked by its own CSP (feature/disclosure mismatch, no leak)

**File:** `apps/vedetta/index.html:5` (CSP `connect-src`), custom fetch at **:2018**, UI at **:768-775**.

**Failure:** Settings offers a "Custom endpoint" quote provider taking an arbitrary user URL template (`https://your-host/quote?s={symbol}`). But `connect-src` is pinned to exactly `api.anthropic.com api.coingecko.com api.frankfurter.dev finnhub.io query1.finance.yahoo.com`. Any custom host is therefore **blocked by CSP** and the fetch throws; the feature silently fails for the user.

**Security read:** this is net **positive** for containment — CSP correctly refuses to let a user-typed (undisclosed) host receive symbol lookups, so there is no exfiltration channel. The defect is only that the UI advertises a capability the CSP forbids. **Fix — SMALL/safe (apply now):** either (a) remove/disable the Custom-endpoint option in this browser build and say it is available only in the desktop/Tauri shell (consistent with how Yahoo-CORS is already explained at `:757`), or (b) leave code as-is but add one line to the Custom radio-card help text noting it works only in the Postern shell, not the pinned-CSP web page. Do **not** widen `connect-src` to a wildcard — that would defeat the disclosed-hosts guarantee.

---

## Verified-correct (no action) — the security-relevant things that are *right*

**Chinese Wall / Brewer–Nash — correct.** `wallCheck` (`:919-928`) denies access to any volume whose `classId` matches a class the user has already bound to via a *different* `groupId`; first access binds (`accessVolume` :1425-1446). The only access path (`accessVolume`) evaluates `rbacCheck` **then** `wallCheck` and returns early on either failure — the "Open volume" button is rendered only for the `open` state (`:1495`), and no discretionary override path exists. A conflict-of-interest access cannot slip through.

**RBAC/ABAC — no bypass, no privilege escalation.** `rbacCheck` (`:930-936`) requires the role to be entitled to the volume family **and** `user.clearance ≥ vol.clearance`. `it-admin` and `compliance-officer` carry `volumes: []` (`:943-944`), so admin roles can open **no** data volumes — "admin ≠ access" is actually enforced, not just claimed. Single-role assignment means the declared SOD pair (`:947`) has no multi-role escalation surface in the demo.

**Dual-control escrow — one party cannot act alone.** Shares are real Shamir 2-of-3 over GF(256) (`:862-895`), each ECIES-sealed to a *distinct* officer's P-256 key at provisioning (`:1187-1189`). Release requires two officers; `officerApprove` is called with `ob.approvals` as `excludeIds` (`:1360-1363`, dialog filter `:1238-1240`), so the same officer cannot supply both approvals. Each approval unlocks only that officer's own sealed key and signs a release record; the release is chained into the audit log **before** reconstruction (`:1373-1381`). The residual "two officers colluding can read company data" is escrow's stated purpose, disclosed at `:686-689`, not a silent backdoor.

**Output escaping / XSS — clean across all four.** Every user- or model-controlled string reaching an `innerHTML` sink is passed through `escapeHtml` (Consiglio org/user/officer names, audit details, policy JSON; Store compare table; the status lines in sotto/store/vedetta escape interim voice transcript and error text). Result lists in Store and Vedetta's board are built with `createElement`+`textContent`. No unescaped voice/text path reaches a DOM or `exec` sink.

**Voice-search parameterization — no injection.** Store's concierge output is constrained by `normalizeFilters` (`store` :1348-1360): every field is enum/whitelist-validated, `query_text` is length-capped and tokenized through an alphanumeric-only regex; the search is deterministic local code. Vedetta URL-encodes every symbol before every fetch (`encodeURIComponent` at :1954, :1993, :2018, :2045, :2083) and normalizes symbols through `normalizeSymbol`/`classify`.

**CSP — pinned to disclosed hosts only.** All four: `default-src 'none'`, `base-uri 'none'`, `form-action 'none'`, `connect-src` restricted. Enterprise/sotto/store pin `api.anthropic.com` alone; Vedetta adds exactly the four market-data hosts it discloses in the Privacy ledger (`:916-994`). `script-src/style-src 'unsafe-inline'` is required for the self-contained single-file design and acceptable given `default-src 'none'` and no remote script origins.

**Voice pipeline privacy — honestly bounded.** All three voice apps use push-to-talk only (mic captured only while held; `window.blur` force-stops — sotto :1127, store :1966, vedetta :1723), disclose that Web Speech audio may reach the browser vendor, label the on-device Whisper slot as not-yet-bundled, and generate TTS on-device via `speechSynthesis` (network voices flagged "⚠ network voice"). BYO keys are labeled less-private: Vedetta's Finnhub key is user-supplied and sent as an `X-Finnhub-Token` header, never in the URL (`:1990-1994`).

**No covert telemetry / no extra parties.** No analytics, beacons, or hidden endpoints in any of the four. The only network destinations are the ones in each app's CSP and Privacy panel. No revenue/token machinery touches these apps.

**Honesty guardrails intact.** Enterprise controls are transparent (named admin-of-record, permanent unremovable transparency panel `:596-605`, "no hidden-monitoring mode… by refusal"); the permanent NOT-LEGAL-ADVICE strip has no code path that hides it (`:393-401`); escrow/BYO-key/limits are all disclosed rather than papered over.

---

## Five-line summary

1. **Fix now (MEDIUM):** Consiglio writes the Anthropic API key to plaintext localStorage (`postern-enterprise/index.html:973,1627`) — the one flagged gap; seal it by porting the existing `KeySeal` module from sotto/store/vedetta (SMALL/safe copy-paste + one settings row).
2. Consiglio's crypto-governance keys (admin/officer signing + ECDH) are already correctly sealed under AES-256-GCM/PBKDF2 — only the LLM key is exposed.
3. Authz core is correct as written: Brewer–Nash walls cannot be bypassed, RBAC/ABAC enforces "admin ≠ access," and 2-of-3 dual-control escrow prevents any single officer acting alone.
4. The three self-contained UIs escape all output, pin CSP to disclosed hosts, keep voice push-to-talk with honest cloud/on-device boundaries, and carry no covert telemetry.
5. Only low-severity items remain: local-only audit tamper-evidence (disclosed; product replicates off-IT) and Vedetta's Custom-endpoint option being (correctly) blocked by its own CSP — a disclosure mismatch, not a leak.
