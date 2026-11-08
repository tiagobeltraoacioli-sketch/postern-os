// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Gramota — UI wiring (DOM only). All decision logic lives in core.js (tested).
// This file renders views, mirrors the server guards for UX, calls the same-origin
// /license/* and /gramota/* endpoints, and drives the registration bot. It holds NO
// crypto: it renders the vendor-signed bundle the server returns and hands the
// private key to the user to keep.
//
// The one privacy-critical seam that lives HERE (not in core.js) is byokAssist():
// the orchestration that redacts + hard-asserts-no-PII BEFORE any BYOK network
// call. It is exported and dependency-injectable so byok-privacy.test.mjs can
// drive the real function under Node with a fake fetch (no DOM, no real network).
// All DOM wiring is deferred behind a `typeof document` guard so importing this
// module in a test runner does not touch the DOM.

import core from "./core.js";

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };

// collected corporate context (client-side only)
const ctx = { duns: null, role: null, attestation: false, kyc: null };

// registrar session + BYOK shell state (module-level; mutated by the DOM handlers)
let session = core.newSession();
const byok = { enabled: false, key: null, consentText: false, consentPII: false };

// Anthropic Messages endpoint — the ONLY external origin BYOK ever reaches.
export const ANTHROPIC_ENDPOINT = "https://api.anthropic.com/v1/messages";

// ---- view navigation -----------------------------------------------------
const VIEWS = ["home", "duns", "role", "kyc", "result", "bot"];
const RAIL_FOR = { home: "tier", duns: "duns", role: "role", kyc: "kyc", result: "result" };
function show(view) {
  for (const v of VIEWS) { const n = $("v-" + v); if (n) n.hidden = v !== view; }
  const rail = $("rail");
  rail.hidden = !(view in RAIL_FOR) || view === "home";
  const order = ["tier", "duns", "role", "kyc", "result"];
  const idx = order.indexOf(RAIL_FOR[view]);
  rail.querySelectorAll(".step").forEach((s) => {
    const si = order.indexOf(s.getAttribute("data-step"));
    s.setAttribute("data-on", si === idx ? "1" : "0");
    s.setAttribute("data-done", si >= 0 && si < idx ? "1" : "0");
  });
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// ---- V3 KYC seam handoff -------------------------------------------------
async function probeKyc() {
  // GET the seam's advertised default so the copy is honest before we run it.
  try {
    const r = await fetch("/gramota/kyc", { method: "GET" });
    if (r.ok) { const j = await r.json(); if (j.default) $("kycDefaultNote").innerHTML = "Provider status: <b>" + escapeHtml(j.default) + "</b>"; }
  } catch { /* offline is fine — the button still runs the check */ }
}

function renderKycOutcome(result) {
  const out = $("kycOutcome"); out.innerHTML = "";
  const card = el("div", "kyc-card");
  if (result.decision === "pass") {
    card.classList.add(); out.className = "";
    card.appendChild(el("h3", null, "Passed — assurance: " + (result.assurance || "self-declared")));
    card.appendChild(el("p", null, result.notice || "Proceeding to issuance."));
    out.appendChild(card);
    const btn = el("button", "btn btn-acc", "Issue corporate master →");
    btn.addEventListener("click", () => issue({ tier: "corporate-master", duns: ctx.duns, role: ctx.role, attestation: true }));
    const row = el("div", "btnrow"); row.appendChild(btn); out.appendChild(row);
  } else if (result.decision === "pending") {
    card.appendChild(el("h3", null, "KYC in review"));
    card.appendChild(el("p", null, "You stay on freemium until it clears — no charge, nothing locked. Return any time to check. " + (result.notice || "")));
    out.appendChild(card);
  } else {
    const err = el("div", "errstrip");
    err.appendChild(el("h3", null, "Identity check did not pass"));
    err.appendChild(el("p", null, "No corporate master is issued. Your freemium is untouched. You can retry or contact support."));
    out.appendChild(err);
  }
}

// ---- issuance (V4) — POST /license/master, render the vendor-signed bundle
async function issue(body) {
  show("result");
  $("resultTitle").textContent = body.tier === "corporate-master" ? "Corporate master license" : "Business freemium license";
  $("resultBody").innerHTML = "";
  $("bundle").textContent = "Issuing…";
  $("absorbPrompt").innerHTML = "";
  let j, ok;
  try {
    const r = await fetch("/license/master", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
    });
    j = await r.json(); ok = r.ok;
  } catch (err) {
    $("bundle").textContent = "";
    $("resultBody").appendChild(strip("errstrip", "Request failed: " + err));
    return { ok: false };
  }
  if (!ok) {
    $("bundle").textContent = "";
    const msg = j.error || ("HTTP error");
    $("resultBody").appendChild(strip("errstrip",
      (j.dnb ? "DUNS did not resolve at Dun & Bradstreet — issuance refused. " : "") + msg));
    // The refusal never touches an existing freemium install.
    $("resultBody").appendChild(strip("standin", "Your freemium (if any) is untouched. Offline verification and any installed token are unaffected."));
    return { ok: false };
  }
  // Success — render the bundle honestly.
  const notice = j.notice || "";
  $("resultBody").appendChild(strip("okstrip", (body.tier === "corporate-master" ? "Corporate master issued. " : "Freemium master issued. ") + notice));
  $("bundle").textContent = JSON.stringify(j, null, 2);
  if (body.tier === "corporate-master") renderAbsorbPrompt();
  return { ok: true };
}

// Absorb prompt — offered only as guidance; the mint happens in Consiglio.
function renderAbsorbPrompt() {
  const plan = core.planAbsorb([{ label: "Desktop 1" }, { label: "Desktop 2" }, { label: "Desktop 3" }], "revoke");
  const box = el("div", "standin");
  box.appendChild(el("b", null, "Bring your freemium desktops onto this corporate license? "));
  box.appendChild(document.createTextNode(
    "In Consiglio we mint a corporate sub for each freemium device (seat cost " + plan.seatCost + " — corporate is unlimited) and retire the freemium master. "));
  const ul = el("ul"); for (const n of plan.notes) ul.appendChild(el("li", null, n)); box.appendChild(ul);
  const row = el("div", "btnrow");
  const a = el("a", "btn btn-ghost", "Promote 3 desktops in Consiglio →"); a.href = "/apps/enterprise/#absorb";
  row.appendChild(a); box.appendChild(row);
  $("absorbPrompt").appendChild(box);
}

// ==========================================================================
// The registration bot (registrar) — deterministic walker + optional BYOK shell.
// ==========================================================================
function botSay(text) { const li = el("li", "msg bot", text); $("transcript").appendChild(li); scrollTranscript(); }
function botSys(text) { const li = el("li", "msg sys", text); $("transcript").appendChild(li); scrollTranscript(); }
function userSay(text) { const li = el("li", "msg user", text); $("transcript").appendChild(li); scrollTranscript(); }
function scrollTranscript() { const t = $("transcript"); t.scrollTop = t.scrollHeight; }

function renderChips() {
  const chips = $("botChips"); chips.innerHTML = "";
  const st = session.state;
  const add = (label, fn) => { const c = el("button", "chip", label); c.type = "button"; c.addEventListener("click", fn); chips.appendChild(c); };
  if (st === "start") {
    add("I'm the owner — unlimited users", () => advance({ tier: "corporate-master" }, "Corporate master, please."));
    add("Just 3 desktops, no DUNS", () => advance({ tier: "business-freemium" }, "Business freemium, please."));
  } else if (st === "role") {
    add("I'm the owner", () => advance({ role: "owner" }, "I'm the owner."));
    add("Authorized manager", () => advance({ role: "manager" }, "I'm an authorized manager."));
  } else if (st === "attestation") {
    // The attestation must be a REAL checkbox — render it, never a chip that ticks it.
    const wrap = el("div", "checkline");
    const cb = el("input"); cb.type = "checkbox"; cb.id = "botAttest";
    const lb = el("label"); lb.setAttribute("for", "botAttest");
    lb.innerHTML = "I attest I am the <b>owner or an authorized manager</b> of the DUNS holder, with authority to accept these terms, and understand KYC validation happens at the 6-month renewal.";
    wrap.appendChild(cb); wrap.appendChild(lb); chips.appendChild(wrap);
    cb.addEventListener("change", () => { if (cb.checked) advance({ attestation: true }, "I tick the attestation."); });
  } else if (st === "kyc") {
    add("Run identity check", () => runBotKyc());
  } else if (st === "issue_corporate") {
    add("Issue my corporate master", () => runBotIssue("corporate-master"));
  } else if (st === "issue_freemium") {
    add("Issue my freemium master", () => runBotIssue("business-freemium"));
  }
}

function advance(input, echo) {
  if (echo) userSay(echo);
  const res = core.stepRegistrar(session, input);
  session = { state: res.state, collected: res.collected };
  if (res.error) { botSay(res.error); renderChips(); return; }
  botSay(res.prompt);
  renderChips();
  // The bot NEVER mints — issuance is an explicit user action via the chip above.
}

async function runBotKyc() {
  botSys("Handing off to the sealed identity check — the bot does not see your documents.");
  let result;
  try {
    const r = await fetch("/gramota/kyc", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ duns: session.collected.duns, role: session.collected.role }) });
    result = await r.json(); if (!r.ok) throw new Error(result.error);
  } catch (err) { result = { decision: "pending", ref: "kyc-client-error", notice: String(err) }; }
  botSys("KYC decision: " + result.decision + (result.assurance ? " (assurance: " + result.assurance + ")" : ""));
  advance({ kyc: result.decision }, null);
}

async function runBotIssue(tier) {
  botSys("Requesting issuance from the server — the bot holds no key; the server signs.");
  const body = tier === "corporate-master"
    ? { tier, duns: session.collected.duns, role: session.collected.role, attestation: session.collected.attestation === true }
    : { tier };
  const r = await issue(body); // reuses the same V4 renderer + secret-key callout
  const applied = core.applyIssuance(session, r && r.ok === true, tier);
  session = { state: applied.state, collected: applied.collected };
  show("bot");
  botSay(applied.prompt);
  renderChips();
}

// ==========================================================================
// BYOK PRIVACY SEAM — the privacy-critical orchestration (tested in
// byok-privacy.test.mjs). Contract, in order, fail-closed:
//   1. redact rawText UNCONDITIONALLY via core.redactPII(rawText, known);
//   2. hard-assert core.assertNoPII(safe, known) — if it THROWS, send NOTHING
//      (no fetch at all) and surface a skip notice;
//   3. only then call the model, and the ONLY thing ever put on the wire is the
//      redacted `safe` string — never rawText, never DUNS/legalName.
// Dependencies are injectable (deps) so the test can supply a fake fetch,
// fixture session/byok state, and a stub core, with zero DOM and zero network.
// The app calls it with no deps, binding the live module state + global fetch.
// ==========================================================================
export async function byokAssist(rawText, input, deps = {}) {
  const c = deps.core || core;
  const sess = deps.session || session;
  const b = deps.byok || byok;
  const fetchImpl = deps.fetchImpl || (typeof fetch !== "undefined" ? fetch : null);
  const say = deps.botSys || botSys;
  const endpoint = deps.endpoint || ANTHROPIC_ENDPOINT;

  // Redact UNCONDITIONALLY, then hard-assert no PII survived (fail-closed).
  const known = { duns: sess.collected.duns, legalName: sess.collected.legalName };
  const safe = c.redactPII(rawText, known);
  try { c.assertNoPII(safe, known); } catch (e) { say("Skipped model call — " + e.message); return; }
  if (!fetchImpl) return;
  try {
    const r = await fetchImpl(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": b.key, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({
        model: "claude-3-5-haiku-latest", max_tokens: 24,
        system: "Classify the user's intent into exactly one token: 'owner', 'manager', 'freemium', 'corporate', or 'unknown'. The text is redacted; never ask for PII.",
        messages: [{ role: "user", content: safe }],
      }),
    });
    if (!r.ok) return;
    const j = await r.json();
    const out = (j && j.content && j.content[0] && j.content[0].text || "").toLowerCase();
    if (sess.state === "start") { if (out.includes("freemium")) input.tier = "business-freemium"; else if (out.includes("corporate")) input.tier = "corporate-master"; }
    if (sess.state === "role") { if (out.includes("owner")) input.role = "owner"; else if (out.includes("manager")) input.role = "manager"; }
  } catch { /* model unreachable — deterministic path already ran; no PII exposed */ }
}

// ---- helpers -------------------------------------------------------------
function strip(cls, text) { const n = el("div", cls); n.textContent = text; return n; }
function escapeHtml(s) { return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }

// ==========================================================================
// DOM wiring + boot — deferred so importing this module in a test runner (no
// `document`) is side-effect-free. Everything below only runs in the browser.
// ==========================================================================
function boot() {
  // ---- theme -------------------------------------------------------------
  $("themeToggle").addEventListener("click", () => {
    const root = document.documentElement;
    const cur = root.getAttribute("data-theme");
    const next = cur === "light" ? "dark" : cur === "dark" ? "light"
      : (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "dark" : "light");
    root.setAttribute("data-theme", next);
  });

  document.querySelectorAll("[data-goto]").forEach((b) => b.addEventListener("click", () => show(b.getAttribute("data-goto"))));

  // ---- V0 tier picker ----------------------------------------------------
  $("pick-freemium").addEventListener("click", () => issue({ tier: "business-freemium" }));
  $("pick-corporate").addEventListener("click", () => { show("duns"); });

  // ---- V1 DUNS -----------------------------------------------------------
  $("dunsNext").addEventListener("click", () => {
    const v = core.validateDuns($("duns").value);
    if (!v.ok) { $("dunsHint").textContent = "That isn't a 9-digit DUNS number — please enter exactly 9 digits."; return; }
    ctx.duns = v.value;
    show("role");
  });

  // ---- V2 role + attestation --------------------------------------------
  $("attestation").addEventListener("change", (e) => { $("roleNext").disabled = !e.target.checked; });
  $("roleNext").addEventListener("click", () => {
    const v = core.validateCorporate({ duns: ctx.duns, role: $("role").value, attestation: $("attestation").checked });
    if (!v.ok) { alert(v.error); return; }
    ctx.role = v.body.role; ctx.attestation = true;
    show("kyc");
    probeKyc();
  });

  // ---- V3 KYC run --------------------------------------------------------
  $("kycRun").addEventListener("click", async () => {
    $("kycOutcome").innerHTML = "";
    const note = el("div", "standin", "Running identity check…");
    $("kycOutcome").appendChild(note);
    let result;
    try {
      const r = await fetch("/gramota/kyc", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ duns: ctx.duns, role: ctx.role }),
      });
      result = await r.json();
      if (!r.ok) throw new Error(result.error || ("HTTP " + r.status));
    } catch (err) {
      // Fail-closed: an error is a hold, never a silent pass.
      result = { decision: "pending", assurance: "self-declared", ref: "kyc-client-error", notice: String(err) };
    }
    ctx.kyc = result.decision;
    renderKycOutcome(result);
  });

  // ---- issuance bundle copy ----------------------------------------------
  $("copyBundle").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText($("bundle").textContent); $("copyBundle").textContent = "Copied ✓"; setTimeout(() => ($("copyBundle").textContent = "Copy bundle"), 1500); } catch { /* clipboard blocked — the <pre> is selectable */ }
  });

  // ---- bot toggles -------------------------------------------------------
  $("botToggle").addEventListener("click", () => {
    const on = $("botToggle").getAttribute("aria-pressed") === "true";
    $("botToggle").setAttribute("aria-pressed", String(!on));
    if (!on) { show("bot"); if (!$("transcript").childElementCount) botSay(core.STATES.start.prompt); renderChips(); }
    else show("home");
  });
  $("botByokToggle").addEventListener("click", () => { const b = $("byokBox"); b.hidden = !b.hidden; });

  $("botForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const text = $("botInput").value.trim();
    if (!text) return;
    $("botInput").value = "";
    userSay(text);
    // Deterministic parse FIRST (PII-safe). The LLM never sees DUNS/names.
    let input = { text };
    if (session.state === "duns") { const d = core.normalizeDuns(text); if (d) input.duns = d; }
    if (session.state === "role") { const r = core.parseRole(text); if (r) input.role = r; }
    if (session.state === "start") { const t = core.parseTier(text); if (t) input.tier = t; }
    // Optional BYOK assist only for UNRESOLVED, NON-PII intent (never on DUNS text).
    if (byok.enabled && session.state !== "duns" && !(input.tier || input.role)) {
      await byokAssist(text, input);
    }
    advance(input, null);
  });

  // ---- BYOK least-private shell (double consent; PII wall) ----------------
  $("byokEnable").addEventListener("click", async () => {
    if (!confirm("Consent 1 of 2: use YOUR OWN Anthropic model to interpret your free-text answers? This is the least-private path — text you type may be sent to a third-party model you configure.")) return;
    if (!confirm("Consent 2 of 2: I understand DUNS, names, and documents are NEVER sent — only redacted, non-PII intent text. This wall cannot be opened by consent.")) return;
    const key = prompt("Paste your Anthropic API key (kept in memory only, never persisted, never sent to Postern):");
    if (!key) return;
    byok.enabled = true; byok.key = key; byok.consentText = true; byok.consentPII = true;
    $("botModel").textContent = "claude (BYOK · least-private)";
    $("botLock").textContent = "BYOK on · PII redacted before every call";
    botSys("BYOK assist enabled. PII is redacted to [DUNS]/[NAME] before any model call; DUNS text is never sent at all.");
  });

  // boot view
  show("home");
}

if (typeof document !== "undefined") boot();
