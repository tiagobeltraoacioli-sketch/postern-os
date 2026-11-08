# Feasibility Analysis — "Dragoman": real-time translation + stenographic meeting notes

**Status:** decision document + build spec. Nothing is built yet.
**Scope:** a second Postern Labs web app in the Sotto family (`apps/sotto/index.html` is the
reference architecture), with two modes: (1) near-real-time speech translation and
(2) a stenographic meeting-notes writer with encrypted archival.
**Judged against:** `docs/POSTERN-LABS.md` (privacy/security-first, honesty, audit-gating) and
`docs/POSTERN-APPS-ROADMAP.md` (permissive-license rule: MIT / Apache-2.0 / BSD; MPL only as
unmodified aggregation; **AGPL/GPL forbidden — no fork, no embed**).

---

## Executive summary

| Question | Answer |
|---|---|
| Mode 1 — speech translation, browser-first | **VIABLE-WITH-CAVEATS** — works today via Web Speech STT → user's-own-Claude (Haiku 4.5) → on-device TTS. The honest caveat: it is *consecutive* interpretation with ~1–3 s lag per utterance, not true simultaneous; and browser STT may send audio to the browser vendor. Fully-on-device path exists but is heavy/experimental → stub, exactly like Sotto's Whisper slot. |
| Mode 2 — steno meeting notes | **VIABLE-WITH-CAVEATS** — continuous transcription + incremental LLM structuring (Sonnet 5 by default) works and is cheap (typically well under $1/meeting-hour). The honest caveat: **the browser has no speaker diarization** — attribution is manual-tap or content-inference, both flagged as heuristics. |
| Secure encrypted archival | **VIABLE** — WebCrypto AES-256-GCM, key derived by native PBKDF2-SHA-256 (600k iterations), IndexedDB at rest, export/import of the encrypted vault, one-click erase. Zero dependencies. Honest limit stated: a browser origin is not a hardware vault. |
| Self-contained single file, only network = `api.anthropic.com` | **YES for the MVP** (plus the disclosed browser speech service). On-device WASM models are 40–300 MB and cannot honestly live inside "one file, one network destination" — addressed below; stubbed in the prototype. |
| Overall | **GO — build the prototype now.** |

---

## 1. Product framing and ethos fit

Sotto's identity — static single HTML file, no server, no account, no telemetry, user's own
Anthropic API key called directly from the browser, honest privacy ledger that refuses to say
"100% private" — maps onto this product almost perfectly, and the two modes are *more*
ethos-defining than a voice assistant:

- **Translation is a privacy disaster today.** Google Translate / DeepL conversation modes ship
  your speech and text to an ad-tech or SaaS vendor under *their* terms. An interpreter whose only
  cloud contact is the user's own Claude key (and, disclosed, the browser's STT service) is a real
  differentiator, honestly framed.
- **Meeting notes are worse.** Otter/Fireflies-class products retain full meeting audio and
  transcripts server-side. "Your meeting never touches anyone's server but Anthropic's, under your
  own key, and the archive is encrypted with a passphrase only you know" is the strongest privacy
  pitch in the portfolio short of the hygiene app.
- It consumes nothing from the Bloch protocol (correct — Postern products are independent), and
  the archival design points forward to **Postern Vault** (same AEAD-vault mental model, TEE
  key-wrap in the real product) and **Postern Seal** (a future opt-in "prove these minutes existed
  at time T" hash-anchor is the scrub-by-default / prove-by-opt-in pattern again — explicitly
  out of scope for the prototype).

Naming rule respected: no "Bloch", not "Sotto". Proposed name: **Dragoman** (§9).

---

## 2. Mode 1 — real-time translation: technical viability

### 2a. Cloud-assisted path (works today) — Web Speech STT → own-key Claude → on-device TTS

**Pipeline.** `SpeechRecognition` (`continuous: true`, `interimResults: true`, `lang` = source
language) → segment transcript on final results / pause boundaries → POST each segment to
`api.anthropic.com/v1/messages` (streaming SSE, Haiku 4.5) with a short rolling context of prior
segments + their translations (coherence for pronouns/terminology) → render translation as it
streams → optionally speak it via `speechSynthesis` with a target-language voice.

**Latency, honestly.** Web Speech emits interim results within a few hundred ms, but *final*
results only ~0.5–1.5 s after a pause; Haiku 4.5 first-token latency is roughly 0.3–0.8 s; a
one-sentence translation streams in well under a second. **Net: ~1–3 s behind the speaker per
utterance.** That is *consecutive* interpretation with low lag. The UI and copy must not claim
"simultaneous" — call it "near-real-time" and say the lag out loud. An optimization worth having:
translate on *stable interim* text (interim unchanged for ~600 ms) rather than waiting for the
final result; costs a few duplicate requests, buys ~1 s.

**Chunking strategy.** One Claude request per utterance/sentence, not per word (Web Speech gives
sentence-scale finals anyway). System prompt pins the translator role hard: "output ONLY the
translation, no commentary, no quotes, preserve register". Rolling context window: last ~6
source/target pairs, capped; long sessions never grow unbounded.

**Quality.** Haiku 4.5 is genuinely strong at translation for major language pairs — comfortably
better than the on-device NMT options below, with idiom/register handling small NMT models lack.
Weak points to disclose: rare languages, heavy code-switching, and STT errors upstream (garbage
in, fluent garbage out — the UI should always show the *source* transcript next to the
translation so the user can spot mis-hearings).

**Directions & conversation mode.** Web Speech requires `lang` to be fixed *before* recognition
starts — the browser will not language-detect speech for you. Therefore:
- **Listen mode (one direction):** pick source + target; continuous capture with an auto-restart
  loop (Chrome ends recognition after silence; restart in `onend` while the mode is active). This
  means the mic is **continuously hot** — unlike Sotto's push-to-talk, so the MIC LIVE badge must
  be persistent and the privacy panel must call out continuous capture explicitly.
- **Conversation mode (back-and-forth):** two big push-to-talk targets — "I speak A" / "They
  speak B". Holding a side starts recognition in that language and translates to the other, with
  TTS reply in the listener's language. This is the honest design; hands-free automatic
  language identification is **not viable** with Web Speech (the recognizer is already locked to
  one language, so there is no reliable signal to detect from). Say so rather than faking it.

**Verdict for 2a: viable now**; all of it is engineering on APIs Sotto already exercises.

### 2b. Fully on-device path (WASM) — higher privacy, heavier, experimental

- **STT:** whisper.cpp compiled to WASM (**MIT**; Whisper weights **MIT**) or Transformers.js
  (**Apache-2.0**) + ONNX Runtime Web (**MIT**) running whisper-tiny/base or distil-whisper
  (**MIT**). Model sizes ~40–150 MB quantized. On a decent laptop, tiny/base runs near real-time
  in WASM (SIMD/threads required — needs COOP/COEP headers or single-thread fallback); on phones
  it is marginal. Quality below the browser's cloud STT for accents/noise.
- **MT:** the honest option set, licenses verified:
  - **Bergamot/Marian** (`bergamot-translator`, the Firefox local-translation engine): **MPL-2.0**,
    models (`mozilla/firefox-translations-models`) also MPL — usable **only as unmodified
    aggregation** under the roadmap rule, flagged. ~20–40 MB per language pair, decent quality for
    major European pairs, real-time on CPU. The strongest on-device MT candidate.
  - **`translateLocally`**: GPL-family desktop app — **disqualified as code** (no fork, no embed);
    concept reference only. (It consumes the same Bergamot models, which remain MPL.)
  - **OPUS-MT (Helsinki-NLP) models via Transformers.js**: runtime Apache-2.0/MIT, models
    **CC-BY-4.0** (attribution required — acceptable, satisfy attribution in the About panel).
    Quality per-pair moderate; hundreds of pairs available.
  - **argos-translate**: MIT, but Python/desktop — not a browser path; concept only.
  - **NLLB-200**: **CC-BY-NC-4.0 — disqualified** (non-commercial clause; Postern sells products).
  - **LibreTranslate / ONLYOFFICE-style servers: AGPL — disqualified**, and they're servers anyway.
- **Trade-off, stated plainly:** cloud path = lower privacy (browser vendor may get audio; text
  reaches Anthropic) but works today with the best quality. On-device path = nothing leaves the
  machine, but 100–300 MB of models, WASM performance cliffs, and clearly lower translation
  quality. Ship the first, wire the engine interface for the second, stub it honestly — the exact
  pattern Sotto already established with `OnDeviceWhisperEngine.available: () => false`.

---

## 3. Mode 2 — stenographic meeting notes: technical viability

**Capture.** Same continuous Web Speech loop as Listen mode (auto-restart on `onend`), producing
timestamped transcript segments held in tab memory. The fully-local fallback: type/paste notes,
or (later) on-device Whisper.

**Structuring.** Incremental summarization — the only approach that survives long meetings:
1. Raw segments accumulate locally, always visible (the "verbatim-ish" steno column).
2. Every ~90–120 s (or ~1,500 chars of new transcript), send Claude: the current **running
   minutes** (structured JSON/markdown state) + the **new raw segments** → get back the updated
   minutes. State is bounded: the model re-emits condensed minutes, so context never grows with
   meeting length; the raw transcript stays local and is never re-sent in full.
3. On "end meeting", one final pass (Sonnet 5 default, Opus 4.8 optional) produces the polished
   deliverable: title, attendees-as-heard, topic sections in terse steno register, **decisions**,
   **action items** (owner/due when stated), open questions, and selected short verbatim quotes.

**Speaker attribution — the honest limits.** The Web Speech API returns text only; the browser
platform has **no diarization**. Options, in honesty order:
- **Manual speaker tap** (a row of speaker chips; tapping tags subsequent segments) — reliable,
  needs a human finger. MVP.
- **LLM content inference** ("I'll take that" / "as Maria said") — flag every inferred
  attribution as `(inferred)`. MVP, clearly labeled.
- **On-device diarization** (pyannote segmentation weights are MIT but HF-gated; sherpa-onnx is
  Apache-2.0) — real, but heavy WASM + raw `getUserMedia` audio pipeline, i.e. the same class of
  work as on-device Whisper. **Stub.**
The privacy panel and the notes header must both say: "speaker labels are manual or inferred —
the browser cannot identify voices."

**Cost, honestly estimated.** A 1-hour meeting ≈ 8–10k spoken words ≈ 12–15k transcript tokens.
With incremental updates (running minutes ~1–2k tokens re-sent ~30×): on the order of 60–120k
input + 30–60k output tokens per hour. At Sonnet 5 rates ($3/$15 per MTok; intro $2/$10) that is
roughly **$0.5–1.5 per meeting-hour**, billed to the user's own key; Haiku 4.5 (~$1/$5) cuts it
~3×. Show a per-session token/cost estimate in the UI — honesty extends to money.

**Verdict: viable now**, with diarization honestly excluded.

---

## 4. Privacy posture — the ledger, spelled out per data path

Mirrors Sotto's ledger style; this is what the in-app Privacy panel must say. **No "100% private"
claim anywhere.**

| # | Data path | Who could see what | Mark |
|---|---|---|---|
| 1 | **Mic audio → browser vendor** (Web Speech, both modes) | In Chrome/Edge and most browsers, speech recognition **sends audio to the browser vendor's servers** for transcription, under that vendor's terms. In Listen/Minutes modes the mic is **continuously hot** while the mode runs (not push-to-talk) — a persistent MIC LIVE badge is mandatory, capture stops on tab blur only by explicit user setting, and stopping the mode kills the recognizer immediately. Zero-audio-leak alternative today: **type/paste text** (fully local until sent to Claude); the on-device Whisper slot is the future fix. | ◮ leaves |
| 2 | **Transcript / minutes text → Anthropic** (both modes) | Each translation segment and each minutes-update is sent from the browser **directly to `api.anthropic.com`**, authenticated with the **user's own key** — no middleman, no Postern server, no logs of ours. Anthropic processes it under the *user's* agreement (their retention terms apply). If the user never sends, nothing is transmitted. | ◮ leaves |
| 3 | **Spoken translations — on-device** | `speechSynthesis` uses the OS's local voices; generated audio does not leave the device. (Some OS voices are network voices — the voice picker must mark them "⚠ network voice", as Sotto does.) | ● local |
| 4 | **On-device engines (future)** | whisper.cpp/Bergamot WASM paths process audio/text entirely in the tab; nothing leaves the machine except the one-time model download (disclosed, opt-in — see §6). | ● local |
| 5 | **API key, settings** | localStorage of this browser only; sent only to `api.anthropic.com`. | ● local |
| 6 | **The archive (saved sessions/minutes)** | Encrypted at rest with AES-256-GCM in this browser's IndexedDB, key derived from a passphrase **we never see and never store**. Anyone with the exported vault file or the disk sees ciphertext only. Honest limits: whoever controls this browser profile while the vault is *unlocked* (XSS, malicious extension, malware, someone at your unlocked machine) can read notes and capture the passphrase as you type it; a browser origin is not a hardware vault (Postern Vault's TEE key-wrap is the real-product fix). Forgotten passphrase = data unrecoverable **by design**. | ● local (encrypted) |
| 7 | **Postern** | Sees nothing. Static page, no server, no account, no telemetry, no analytics. The only network destinations in the code: `api.anthropic.com`, plus the browser's own speech service when voice input is used. One readable HTML file — verify it yourself. | — |

---

## 5. Secure encrypted archival — design

Zero-dependency, WebCrypto-only. This is the piece Sotto doesn't have and the roadmap's Vault
thinking predicts.

**KDF: PBKDF2-SHA-256, 600,000 iterations, 16-byte random salt — chosen over Argon2, and here's
why, honestly.** WebCrypto ships PBKDF2 natively; it costs zero dependencies and keeps the app a
single auditable file. Argon2id is the better KDF (memory-hardness resists GPU cracking), but it
requires a WASM dependency (`hash-wasm`, MIT — license-acceptable). Decision: **PBKDF2 @ 600k
(OWASP-current) for the prototype**, with the KDF identifier stored in the vault header
(`kdf: "PBKDF2-SHA256/600000"`) so an Argon2id upgrade is a versioned migration, not a redesign.
State in the privacy panel that PBKDF2 is weaker than Argon2id against offline GPU attacks on
weak passphrases — so pick a strong passphrase.

**Key handling.**
- `deriveKey` → 256-bit **AES-GCM** `CryptoKey`, `extractable: false`, held **only in JS memory
  while the vault is unlocked**; never written to any storage. Auto-lock on timer/tab-hide (config).
- Passphrase string is not retained after derivation (best effort — JS cannot guarantee zeroization;
  say so).

**Vault format (IndexedDB, db `dragoman-vault`).**
- `meta` record: `{v: 1, kdf, salt(b64), iter, verifier: {iv, ct}}` — verifier is
  `AES-GCM(key, "dragoman-vault-check")`.
- `records` store: one per saved session/minutes: `{id, iv (12-byte random, fresh per write),
  ct, aad: id+"|"+v, createdAt, mode}` — title and body both live *inside* the ciphertext
  (metadata like titles must not leak); `createdAt` is the only plaintext field, disclosed.
- **Wrong passphrase:** GCM authentication fails on the verifier → clean "wrong passphrase or
  corrupted vault" error, no partial plaintext ever produced. (AEAD cannot distinguish wrong key
  from corruption — acceptable, documented.)
- Every record is individually encrypted with a fresh IV; AAD binding prevents record-swapping
  within an exported vault.

**Export / import.** "Export vault" downloads one JSON file: `{meta, records[]}` — pure
ciphertext + KDF params, safe to store on any disk/cloud. Import merges by `id` (skip existing),
validates the verifier against the entered passphrase first. This doubles as the backup story and
the migration story between browsers.

**Erase everything.** Deletes the IndexedDB database, all localStorage keys, aborts in-flight
requests, clears in-memory state — extending Sotto's existing erase semantics. Wording: "the
vault ciphertext is gone from this browser; exported vault files on your disk are yours to delete."

**Durability caveat (must be in the UI):** browsers may evict origin storage under pressure —
call `navigator.storage.persist()` and surface the result; tell users the export file is the
real backup.

---

## 6. Self-contained constraint

**MVP: yes, fully.** One static `index.html`, zero runtime dependencies (Web Speech,
speechSynthesis, WebCrypto, IndexedDB are all platform APIs). The only network destination in the
code is `https://api.anthropic.com`; the browser's speech service is the disclosed second party
when voice is used. Same deployment story as Sotto (open the file / any static host).

**On-device WASM models break "one file" honestly.** whisper-base ≈ 140 MB, Bergamot pair ≈
20–40 MB — not inlineable. Options when the slot is filled:
1. **Lazy-load, opt-in, disclosed:** a settings toggle that says exactly "downloading model X
   (N MB) from `<origin>`; this is the only time this origin is contacted; cached locally
   (Cache Storage) thereafter." The privacy panel's "only network destination" line then gains a
   conditional clause. Acceptable if and only if it is opt-in and disclosed — the honesty
   principle allows a disclosed trade, not a silent one.
2. **Sideload/package:** ship an "offline bundle" (HTML + model files in a folder; or the future
   Postern OS/container packaging). Keeps zero third-party origins; loses single-file.
- **Recommendation:** prototype ships **neither** — the engine slots exist, `available()` returns
  false, and the settings UI shows the honest "not bundled in this prototype" copy, exactly like
  Sotto's Whisper radio button.

---

## 7. Licensing — every proposed dependency

**Prototype runtime dependencies: none.** All platform APIs. Nothing to license-audit beyond our
own file.

Future / optional components, verified:

| Component | License | Status under Postern rule |
|---|---|---|
| whisper.cpp (WASM STT) | MIT | ✅ allowed |
| OpenAI Whisper weights | MIT | ✅ allowed |
| distil-whisper weights | MIT | ✅ allowed |
| Transformers.js (runtime) | Apache-2.0 | ✅ allowed |
| ONNX Runtime Web | MIT | ✅ allowed |
| Marian NMT (core) | MIT | ✅ allowed |
| bergamot-translator (WASM MT engine) | **MPL-2.0** | ⚠️ aggregation of unmodified builds only, flagged (per `deny.toml` policy) |
| mozilla/firefox-translations-models | **MPL-2.0** | ⚠️ same — unmodified aggregation only |
| Helsinki-NLP OPUS-MT models | **CC-BY-4.0** | ✅ acceptable with attribution in the About panel |
| hash-wasm (optional Argon2id) | MIT | ✅ allowed |
| sherpa-onnx (future diarization) | Apache-2.0 | ✅ allowed (model weights re-verify at adoption) |
| translateLocally | GPL-family | ❌ **disqualified** — no fork, no embed; concept only |
| NLLB-200 weights | CC-BY-**NC**-4.0 | ❌ **disqualified** — non-commercial clause |
| LibreTranslate | AGPL-3.0 | ❌ **disqualified** |
| argos-translate | MIT | ➖ license fine but Python/desktop — not a browser path |

Re-verify at adoption (roadmap practice): exact license text of the specific
firefox-translations-models release used; pyannote/diarization weight licenses; any Transformers.js
license change (pin versions).

---

## 8. Prototype scope — MVP vs stub

**MVP (build now):**
1. Mode switch: **Interpret** / **Minutes** (+ shared Settings, Privacy, Vault dialogs).
2. Interpret: source/target language pickers; Listen mode (continuous, persistent MIC LIVE,
   auto-restart); Conversation mode (two push-to-talk sides A↔B); streaming translation via
   Haiku 4.5; on-device TTS of translations (mutable); dual-column source/translation transcript;
   text-input path (type → translate) as the fully-local-input fallback.
3. Minutes: start/stop meeting; live raw transcript column; incremental structured minutes
   (Sonnet 5 default, model selectable); manual speaker chips + `(inferred)` labeling; final
   "close meeting" pass; copy/download as Markdown; session token/cost readout.
4. Vault: create/unlock (passphrase), save session, list/reopen, export/import JSON, erase-all,
   auto-lock. Full crypto design of §5.
5. Honest privacy panel with the §4 ledger; erase-everything; theme toggle; no-key onboarding
   state — all inherited Sotto patterns.
6. STT/MT/TTS behind Sotto-style swappable engine interfaces.

**Stub (wired, visibly disabled, honest copy):**
- On-device Whisper STT engine slot (`available() → false`).
- On-device MT engine slot (Bergamot/OPUS-MT — same shape).
- On-device diarization slot.
- "Seal minutes" (hash/PQ-sign/anchor via Postern Seal) — mention as future opt-in, not present.

**Deliberately not built:** any server component; accounts; auto language detection in
conversation mode (dishonest with Web Speech); audio recording/storage (transcripts only — less
data is the privacy-first default; note it in the panel).

---

## 9. VERDICT

- **Mode 1 — near-real-time translation: VIABLE-WITH-CAVEATS.** Works today on the
  Sotto stack. Caveats to carry honestly in-product: consecutive-not-simultaneous (~1–3 s lag),
  browser-vendor STT exposure, fixed-language recognition (push-to-talk sides in conversation
  mode), on-device path stubbed.
- **Mode 2 — steno minutes: VIABLE-WITH-CAVEATS.** Transcription + incremental LLM structuring +
  encrypted archival all work today at trivial per-meeting cost. Caveat carried honestly: no
  browser diarization — manual/inferred speaker labels only.
- **Overall: GO. Build the prototype now** as a single-file static web app on the Sotto
  architecture.

---

## 10. BUILD SPEC

### Name & identity
- **Name: `Dragoman`** — the historical interpreter-secretary of diplomatic courts, an
  intermediary professionally bound to discretion: interprets *and* keeps the minutes. Fits both
  modes, privacy/sovereignty-flavored, Postern-family, contains neither "Bloch" nor "Sotto".
  (Alternates considered: *Chuchotage* — whispered interpreting, thematic sibling of "sotto voce"
  but hostile to spell; *Hansard* — verbatim-record flavored but translation-blind.)
- Wordmark: `D·RAGOMAN` (Sotto's tick pattern), byline "Postern Labs · interpreter & scribe".
- File: `apps/dragoman/index.html`, `<title>Dragoman — interpreter & minutes · Postern Labs</title>`.

### Visual identity
- Same graphite/ink instrument-panel system as Sotto (copy the CSS variable architecture, dark
  default + light theme + `prefers-color-scheme`), but the accent is **verdigris** — aged-copper
  green, distinct from Sotto's brass: dark theme `--verd: #4fa48d`, `--verd-hi: #6fc4ab`,
  `--verd-dim: #35705f`, `--verd-ink: #0a1512`; light theme `--verd: #1f7a63`. Keep `--live`
  red for mic-hot (unambiguous), `--ok/--warn/--err` as in Sotto.
- Hero: not Sotto's orb — a **two-pane "interpreting desk"**: in Interpret mode, source pane and
  target pane side by side with a persistent MIC LIVE badge and a lag indicator; in Minutes mode,
  raw-steno column (mono font, timestamps) beside the structured-minutes column.

### Architecture (inherit from Sotto, verbatim patterns)
- Single self-contained `index.html`, zero dependencies, `"use strict"`, no build step.
- `meta name="referrer" content="no-referrer"`; no external fonts/CDNs/images.
- localStorage keys namespaced `dragoman.*` (KEY, MODEL_XLATE, MODEL_NOTES, LANG_A, LANG_B,
  VOICE, RATE, MUTE, STT, THEME, AUTOLOCK).
- **Engine interfaces** (Sotto's contract, extended):
  - STT: `{ id, label, available(), start({lang, onInterim, onFinal, onError}), stop() }`
    — `WebSpeechEngine` (implemented, with auto-restart loop for continuous modes) +
    `OnDeviceWhisperEngine` (stub, `available: () => false`).
  - MT: `{ id, label, available(), translate({text, from, to, context, onDelta, signal}) }`
    — `ClaudeTranslateEngine` (implemented) + `OnDeviceBergamotEngine` (stub).
  - TTS: Sotto's `tts` object with per-target-language voice selection (`voice.lang` matching,
    "⚠ network voice" marking).
- State machine on `body[data-state]`: `idle | listening | translating | speaking | minuting`.
- Error mapping: reuse Sotto's `friendlyError` (401/403/404/429/400/529/network) verbatim.

### Claude API (exact shape — same as Sotto's working code)
- `POST https://api.anthropic.com/v1/messages`
- Headers: `content-type: application/json`, `x-api-key: <user key>`,
  `anthropic-version: 2023-06-01`, `anthropic-dangerous-direct-browser-access: true`.
- Body: `{ model, max_tokens, system, messages, stream: true }`; parse SSE
  (`content_block_delta` → `text_delta`) exactly as Sotto's `streamMessage` does. No tools needed
  in v1 (translation and minutes are pure text transforms); `AbortController` for stop/barge-in.
- **Models** (mirror Sotto's selector, per-mode defaults):
  - Translation: **`claude-haiku-4-5-20251001`** (default — speed), `max_tokens` ~512/segment.
  - Minutes structuring: **`claude-sonnet-5`** (default), **`claude-opus-4-8`** (option,
    "most capable, slower"), Haiku option for cost. `max_tokens` ~2048 incremental / ~4096 final.
- Prompts:
  - Translate system prompt: professional interpreter; output ONLY the translation into
    `{target}`; preserve tone/register; never answer or comment; user messages carry the rolling
    `context` pairs + new segment.
  - Minutes system prompt: court-stenographer/minutes-secretary register; input = current minutes
    state + new timestamped segments (+ speaker tags where present); output = full updated
    minutes in a fixed Markdown schema: `# title / attendees-as-heard / ## topics (terse) /
    ## decisions / ## action items (owner, due if stated) / ## open questions / ## notable quotes`;
    mark inferred attributions `(inferred)`; never invent facts not in transcript.

### Archival crypto (implement §5 exactly)
- WebCrypto only: `PBKDF2-SHA-256`, 600,000 iterations, `crypto.getRandomValues` 16-byte salt →
  `AES-GCM` 256-bit non-extractable key; 12-byte fresh IV per record; AAD = record id + vault
  version; verifier record for wrong-passphrase detection; IndexedDB db `dragoman-vault`
  (`meta` + `records`); ciphertext-only JSON export/import; `navigator.storage.persist()`;
  auto-lock timer; erase-all wipes IndexedDB + localStorage + memory. KDF id stored in header for
  the future Argon2id migration.

### UI structure
- Header: wordmark, mode tabs `INTERPRET | MINUTES`, buttons `Vault · Privacy · Settings · ◐`.
- Interpret: language pickers (BCP-47 lists for STT lang + human names), Listen/Conversation
  toggle, two-pane transcript, per-utterance lag chip, mute, stop.
- Minutes: start/end meeting, speaker chips (+ add), raw column + minutes column (updating),
  cost/token readout, "Save to vault", "Download .md", "Copy".
- Vault dialog: create/unlock, list (date + mode only until unlocked-decrypted titles), open,
  export/import, lock now, erase vault.
- Privacy dialog: the §4 ledger verbatim in Sotto's ledger-row style, including the continuous-mic
  disclosure, the diarization disclaimer, the vault limits, and the "what we won't claim" closer.
- Settings: API key (Sotto copy), per-mode model selectors, STT engine radio (Web Speech /
  on-device stub), voice + rate, auto-lock minutes, erase everything.
- Footer: `Dragoman · a Postern Labs instrument · your key, your words, your machine`.

### Acceptance checklist for the prototype
1. Only network destination in code: `api.anthropic.com` (grep-verifiable), plus disclosed
   browser STT when used.
2. Both modes function end-to-end with a user key in Chrome/Edge; typing path works in every
   browser (Web Speech absent → honest degradation message, Sotto-style).
3. Vault round-trip: save → lock → reopen with passphrase → export → erase → import → unlock.
4. Wrong passphrase yields a clean error, never partial plaintext.
5. Privacy panel contains no claim of "100%/fully private"; continuous-mic and diarization
   disclosures present.
6. Zero external dependencies; file passes a read-through audit.
