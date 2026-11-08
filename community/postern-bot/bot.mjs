#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Vestnik — a minimal, honest Telegram FAQ bot for the Postern Labs
// community. Zero dependencies (Node 18+ global fetch). Bring-your-own tokens via
// env; NOTHING is hardcoded and no secret is ever logged.
//
//   TELEGRAM_BOT_TOKEN   from @BotFather
//   ANTHROPIC_API_KEY    your Claude API key (the app-suite BYO-key model)
//   ANTHROPIC_MODEL      optional (default: claude-haiku-4-5-20251001 — cheap FAQ)
//
// Scope: in GROUPS it answers only messages that start with /ask (or /postern),
// or that reply to / @-mention the bot. In private chats it answers any text.
// It refuses price/investment questions up front (defense-in-depth) and grounds
// everything in ./system-prompt.md. It never asks for secrets.
//
// Run:  TELEGRAM_BOT_TOKEN=... ANTHROPIC_API_KEY=... node community/postern-bot/bot.mjs

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const SYSTEM = readFileSync(join(HERE, "system-prompt.md"), "utf8");

const TG_TOKEN = req("TELEGRAM_BOT_TOKEN");
const ANTHROPIC_KEY = req("ANTHROPIC_API_KEY");
const MODEL = process.env.ANTHROPIC_MODEL || "claude-haiku-4-5-20251001";
const TG = `https://api.telegram.org/bot${TG_TOKEN}`;

function req(name) {
  const v = process.env[name];
  if (!v) { console.error(`missing env ${name}`); process.exit(1); }
  return v;
}

// Defense-in-depth: obvious price/investment asks get a firm canned refusal and
// never reach the model. Kept deliberately narrow to avoid false positives.
const PRICE_RE = /\b(pre[çc]o|quanto\s+(vale|custa)|vai\s+valer|when\s+(moon|listing|lambo)|price\s*(target|predict)|should\s+i\s+(buy|sell)|devo\s+(comprar|vender)|moon|pump|listagem|listing|market\s*cap|roi|yield|invest(ir|ment)?)\b/i;
const REFUSAL =
  "Não ajudo com preço/investimento — a moeda Bloch não é security nem ativo: " +
  "sem venda, sem listagem, sem preço, sem retorno prometido, por design. " +
  "Posso explicar como a tecnologia funciona. / I can't help with price or " +
  "investment — the Bloch coin is not a security and not an asset (no sale, no " +
  "listing, no price, by design). Happy to explain how the tech works.";

async function tg(method, body) {
  const r = await fetch(`${TG}/${method}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return r.json();
}

// True only for the group's creator/administrators (used to gate /announce).
async function isAdmin(chatId, userId) {
  if (!userId) return false;
  try {
    const r = await tg("getChatMember", { chat_id: chatId, user_id: userId });
    const s = r?.result?.status;
    return s === "creator" || s === "administrator";
  } catch { return false; }
}

async function ask(question) {
  const r = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": ANTHROPIC_KEY,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: MODEL,
      max_tokens: 700,
      system: SYSTEM,
      messages: [{ role: "user", content: question.slice(0, 4000) }],
    }),
  });
  if (!r.ok) throw new Error(`anthropic ${r.status}`);
  const j = await r.json();
  return (j.content || []).filter((c) => c.type === "text").map((c) => c.text).join("").trim();
}

// ── Moderation ─────────────────────────────────────────────────────────────
// Two-stage & conservative. A cheap pre-screen gates the (paid) classifier, and
// the classifier is told: CRITICISM / SKEPTICISM / HARD QUESTIONS / price &
// founder questions are NEVER removable — only CLEAR abuse (slurs, harassment,
// threats, doxxing, scams/phishing). Requires the bot to be a group admin with
// ban rights and Telegram privacy-mode OFF (so it can see messages). If it lacks
// permission, banChatMember just fails and is logged — nothing crashes.
const MOD_PRESCREEN = /\b(idiot|stupid|scam(mer)?|fraud|golpe|burro|imbecil|ot[áa]rio|vagabund[oa]|lixo|merda|fdp|f\*+ck|fuck|shit|bitch|retard|cuz[ãa]o|arrombad[oa]|kill\s+you|vou\s+te\s+(matar|pegar|foder)|die|btc|eth|bnb|sol|xrp|doge|shib|usdt|pepe|presale|whitelist|pump|1000x|100x|listagem|corretora|exchange|promo|desconto|oferta|cpf|rg)\b|https?:\/\/|t\.me\/|seed\s*phrase|private\s*key|chave\s*privada|palavras?\s*semente|airdrop|dm\s+me|manda\s+dm|\d{3}\.?\d{3}\.?\d{3}-?\d{2}/i;
const MOD_MODEL = process.env.MOD_MODEL || "claude-haiku-4-5-20251001";

async function classifyAbuse(text) {
  const rubric =
    "You are a strict but FAIR moderator for the Postern Labs / Bloch-SIS-PoW community. Classify the MESSAGE. " +
    'Return ONLY compact JSON: {"action":"allow|delete|ban","reason":"short"}. RULES: ' +
    "(1) ALLOW: criticism, skepticism, negative opinions, hard/uncomfortable questions, complaints about the project/founder/coin, price questions about Bloch, on-topic Postern/Bloch discussion, and links to Postern/Bloch resources (posternlabs.com, the gitlab source). Mentioning Bitcoin/BTC as the governance model or for comparison is ALLOW. Never remove someone for merely disagreeing. " +
    "(2) BAN: clear targeted abuse (slurs, hate, harassment, threats of violence, doxxing) or scams/phishing (asking for seed phrases/keys, fake airdrops, impersonating the team). " +
    "(3) DELETE: (a) LGPD/GDPR — a message exposing a person's sensitive personal data / PII without consent (CPF/RG, home address, phone, email, financial or health data, private documents of a third party); (b) advertising or promotion of OTHER cryptocurrencies / tokens / exchanges / presales / airdrops (shilling other coins); (c) unrelated promotional or spam links (ads for products/services unrelated to Postern); (d) borderline personal insults not severe enough to ban. " +
    "(4) When unsure, ALLOW. Default to allow. Do NOT delete on-topic Postern/Bloch discussion or its own links.";
  try {
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": ANTHROPIC_KEY, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: MOD_MODEL, max_tokens: 120, system: rubric, messages: [{ role: "user", content: "MESSAGE:\n" + text.slice(0, 1500) }] }),
    });
    if (!r.ok) return { action: "allow", reason: "classifier error" };
    const j = await r.json();
    const raw = (j.content || []).filter((c) => c.type === "text").map((c) => c.text).join("");
    const m = raw.match(/\{[\s\S]*\}/);
    return m ? JSON.parse(m[0]) : { action: "allow" };
  } catch { return { action: "allow", reason: "moderation exception" }; }
}

async function moderate(msg) {
  const text = msg.text || "";
  const from = msg.from;
  if (!text || !from || from.is_bot) return;
  if (!MOD_PRESCREEN.test(text)) return; // fast path — clearly not abusive, no paid call
  const v = await classifyAbuse(text);
  if (v.action === "ban") {
    await tg("deleteMessage", { chat_id: msg.chat.id, message_id: msg.message_id });
    const r = await tg("banChatMember", { chat_id: msg.chat.id, user_id: from.id });
    console.error(`moderation: BAN user ${from.id} (${v.reason || "abuse"}) ok=${r.ok}${r.ok ? "" : " — needs admin+ban rights"}`);
  } else if (v.action === "delete") {
    await tg("deleteMessage", { chat_id: msg.chat.id, message_id: msg.message_id });
    console.error(`moderation: delete msg from ${from.id} (${v.reason || "incivility"})`);
  }
}

async function reply(chatId, text, replyTo) {
  // Telegram caps messages at 4096 chars.
  for (let i = 0; i < text.length; i += 4000) {
    await tg("sendMessage", {
      chat_id: chatId,
      text: text.slice(i, i + 4000),
      reply_to_message_id: i === 0 ? replyTo : undefined,
      disable_web_page_preview: true,
    });
  }
}

// Decide whether/what to answer for a given message.
function extractQuestion(msg, botUsername) {
  const text = (msg.text || "").trim();
  if (!text) return null;
  const isPrivate = msg.chat?.type === "private";
  const repliesToBot = msg.reply_to_message?.from?.username === botUsername;
  const mentionsBot = botUsername && text.toLowerCase().includes(`@${botUsername.toLowerCase()}`);
  const cmd = text.match(/^\/(ask|postern)(@\w+)?\s+([\s\S]+)/i);
  if (cmd) return cmd[3].trim();
  if (isPrivate) return text;
  if (repliesToBot || mentionsBot) return text.replace(new RegExp(`@${botUsername}`, "ig"), "").trim();
  return null; // ignore ordinary group chatter
}

async function main() {
  const me = await tg("getMe", {});
  const botUsername = me?.result?.username;
  if (!botUsername) { console.error("getMe failed — bad TELEGRAM_BOT_TOKEN?"); process.exit(1); }
  console.log(`Vestnik up as @${botUsername} (model ${MODEL}). No secrets logged.`);

  let offset = 0;
  for (;;) {
    let updates;
    try {
      const r = await tg("getUpdates", { offset, timeout: 30, allowed_updates: ["message"] });
      updates = r.result || [];
    } catch (e) {
      console.error("poll error, retrying:", e.message);
      await new Promise((s) => setTimeout(s, 3000));
      continue;
    }
    for (const u of updates) {
      offset = u.update_id + 1;
      const msg = u.message;
      if (!msg) continue;
      // Moderation runs on ALL group messages (needs admin+ban rights & privacy-mode OFF).
      if (msg.chat?.type && msg.chat.type !== "private") {
        try { await moderate(msg); } catch (e) { console.error("moderation error:", e.message); }
      }
      // /announce <text> — group admins/creator only: post an official notice AND
      // pin it. Needs the bot to be an admin with pin rights. Never touches keys.
      const ann = (msg.text || "").match(/^\/announce(@\w+)?\s+([\s\S]+)/i);
      if (ann) {
        try {
          if (msg.chat?.type === "private") { await reply(msg.chat.id, "/announce only works in the group.", msg.message_id); continue; }
          if (!(await isAdmin(msg.chat.id, msg.from?.id))) { await reply(msg.chat.id, "Only group admins can /announce.", msg.message_id); continue; }
          const sent = await tg("sendMessage", { chat_id: msg.chat.id, text: ann[2].trim(), disable_web_page_preview: true });
          const mid = sent?.result?.message_id;
          if (mid) {
            const p = await tg("pinChatMessage", { chat_id: msg.chat.id, message_id: mid, disable_notification: false });
            if (!p.ok) await reply(msg.chat.id, "Posted, but couldn't pin — make Vestnik an admin with 'Pin Messages' rights.", undefined);
            console.error(`announce by admin ${msg.from?.id}: posted=${!!mid} pinned=${p.ok}`);
          }
          try { await tg("deleteMessage", { chat_id: msg.chat.id, message_id: msg.message_id }); } catch {}
        } catch (e) { console.error("announce error:", e.message); }
        continue;
      }
      const q = extractQuestion(msg, botUsername);
      if (!q) continue;
      try {
        if (PRICE_RE.test(q)) { await reply(msg.chat.id, REFUSAL, msg.message_id); continue; }
        await tg("sendChatAction", { chat_id: msg.chat.id, action: "typing" });
        const answer = await ask(q);
        await reply(msg.chat.id, answer || "…", msg.message_id);
      } catch (e) {
        console.error("answer error:", e.message); // never logs the message content or keys
        await reply(msg.chat.id, "Tive um erro ao responder agora. Tente de novo em instantes. / Hit an error — try again shortly.", msg.message_id);
      }
    }
  }
}

main().catch((e) => { console.error("fatal:", e.message); process.exit(1); });
