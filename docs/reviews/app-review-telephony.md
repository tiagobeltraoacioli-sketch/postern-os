# App review — Telephony & Translation slice

Reviewer: fable5 security + technology (Postern Labs)
Status: **PRE-RELEASE / UNAUDITED**. Read-only review; no code modified.
Scope: `crates/postern-telephony` (SMS/voice via ModemManager over D-Bus + sealed store),
`apps/tolmach` (interpreter/minutes, BYO-key), `apps/tolmach-subscription`
(metering proxy + dual-tier client), `docs/specs/POSTERN-TELEPHONY.md`.

Findings ranked most-severe first. No critical/RCE-class issue found. The honesty
posture across all four artifacts is unusually strong (see "What holds up"); the
findings below are real but mostly MEDIUM/LOW hardening and one overclaim to soften.

---

## 1. MEDIUM — Subscription quota can be overshot; uncapped input tokens; "can never lose money" is overclaimed
**File:** `apps/tolmach-subscription/server/proxy.mjs:404-538` (esp. 413-422, 444-446, 470-477)
· README claim: `apps/tolmach-subscription/README.md:170-172`

Concrete failure (inputs → bad outcome): the hard quota is enforced **before** the
request (`if (u.usd >= tier.budgetUSD)` at :415) but usage is only recorded **after**
the stream finishes (`done()` → `recordUsage` at :470-477, :514). Combined with
`MAX_CONCURRENT_PER_SUB = 4` (:88) and the fact that **only `max_tokens` (output) is
clamped — input tokens are never capped** (:444-446; the only input bound is the 1 MiB
body cap at :87), a subscriber sitting at budget-minus-epsilon can fire 4 concurrent
requests, each with ~250k–300k input tokens (1 MiB of text). Worked example on Pro
(Opus, $5/MTok in): ~$1.5 input + $0.20 output ≈ $1.7/request × 4 ≈ **$6.8 of upstream
spend past the $20 budget (~34% overshoot)**. The README's stated margin is 27%
(:161-168), so a maxed-out adversarial subscriber can push the operator to a small
net loss on tokens — contradicting README:170-172 ("a maxed-out subscriber can never
make the operator lose money on tokens").

Fix — **SMALL/safe (apply now):** soften the README claim to "bounded overspend within
margin" and, in code, add an input-token/`max_tokens`-sum sanity clamp (e.g. reject
requests whose declared size × concurrency could exceed remaining budget) — cheap and
local. **LARGE/defer (human):** proper pre-flight reservation/atomic decrement of a
remaining-budget counter that is debited before forwarding and reconciled after
(needs the SQLite/Postgres store the README already plans, README:230-231).

---

## 2. MEDIUM — No rate-limiting on `/auth/register`; unbounded account creation + email enumeration
**File:** `apps/tolmach-subscription/server/proxy.mjs:355-388`, dispatch at :677

Concrete failure: `POST /auth/register` is unauthenticated and has no rate limit or
CAPTCHA. An attacker can mint unlimited `sub_*` records + 256-bit tokens, growing
`subscribers.json` without bound (the whole store is `JSON.parse`/`JSON.stringify` of
an in-memory object, :163-182) → memory + disk exhaustion DoS. Tokens are inactive
until Stripe/dev-activate, so this is not a spend vector, but it is a cheap
availability attack. Separately, the duplicate-email branch returns **409
"already registered"** (:367-372), which lets an attacker **enumerate which emails
have accounts** — a privacy leak for a privacy product.

Fix — **SMALL/safe (apply now):** rate-limit `/auth/register` by IP and cap total
subscribers; make the duplicate-email response indistinguishable from success
(generic "if this email is new, a token was issued" / send via the real IdP) so it
stops confirming account existence. **LARGE/defer (human):** the real IdP
(email-verify / OIDC / passkeys) the README already flags as stubbed (README:226-227).

---

## 3. LOW — CORS defaults to `*`
**File:** `apps/tolmach-subscription/server/proxy.mjs:79, 222-231`

`ALLOWED_ORIGIN` defaults to `*`, so any web origin can invoke the proxy. Because auth
is a bearer token (not a cookie), the browser won't auto-attach credentials
cross-origin, so this is not a CSRF/credential-theft hole — but a `*` default on a
key-bearing operator proxy is a foot-gun if shipped unset. Documented as "tighten it"
(README:214, :228).

Fix — **SMALL/safe (apply now):** refuse to start (or warn loudly) when
`ALLOWED_ORIGIN === "*"` and `ANTHROPIC_API_KEY` is set, forcing an explicit origin in
any real deployment.

---

## 4. LOW — Telephony store: message bodies zeroized, but numbers/metadata and per-record buffers are not
**File:** `crates/postern-telephony/src/types.rs:58-62, 106-114`; `src/store.rs:78-95`

`SmsMessage::drop` zeroizes `body` (types.rs:58-62), and `SealedTelephonyStore::seal`
zeroizes the aggregate `plain` buffer (store.rs:93). But:
- `SmsMessage.number` (who you texted) and the **entire `CallRecord`** (number,
  direction, outcome, timing — i.e. who you called and when) have **no `Drop`/zeroize**
  (types.rs:106-114). This is exactly the "who-called-whom" metadata the spec's
  privacy ledger (spec §5) treats as sensitive, left lingering in freed RAM.
- In `seal`, each per-record `rec = m.encode()` (store.rs:81, :88) copies the plaintext
  body into a temporary `Vec` that is dropped **without** zeroizing; only the merged
  `plain` is wiped. So plaintext body copies persist on the heap after seal.

The spec/store docs say "message bodies zeroized on drop; plaintext serialization
zeroized after seal" (spec §4, store.rs:12-15) — accurate for bodies, but the claim
reads broader than the implementation for metadata and the intermediate buffers.

Fix — **SMALL/safe (apply now):** derive/impl `Zeroize`+`Drop` on `CallRecord` and add
`number` to `SmsMessage`'s zeroize set; zeroize each `rec` before it drops in `seal`.
Or tighten the doc to say only bodies are wiped. Either closes the gap.

---

## 5. LOW — Dialer: emergency-only gate fails open on D-Bus read error; dialed number unvalidated
**File:** `crates/postern-telephony/src/voice.rs:74-95`

`if voice.emergency_only().await.unwrap_or(false)` (:76): if the D-Bus property read
**fails**, it is treated as "not emergency-only" and the dial proceeds. For normal
numbers this is the benign direction (the carrier rejects if truly emergency-only),
but it means the gate the spec relies on (spec §3 "refuse politely if
`Voice.EmergencyOnly`") is silently bypassed on any transient read error rather than
surfaced. Separately, `dial(number)` passes `number` straight into `create_call` with
no shape validation (:79-83) — untrusted call sites could dial arbitrary/premium
numbers; validation is left entirely to the (future) UI.

Fix — **SMALL/safe (apply now):** treat a failed `emergency_only()` read as `NotReady`
(surface it) instead of `unwrap_or(false)`; add a minimal E.164/`+`-digit sanity check
in `dial` before handing the string to the modem. Both are local and non-breaking.

---

## 6. LOW — Metering recorded after the stream + debounced 250 ms save → unmetered spend on crash
**File:** `apps/tolmach-subscription/server/proxy.mjs:170-183, 202-218, 470-477`

Usage is recorded in `done()` after the stream (:470-477) and persisted via a 250 ms
debounced `scheduleSave` (:171-174). If the process dies mid-stream or within the
debounce window, tokens are spent upstream but never counted → the subscriber gets
free usage and the quota under-reports. Bounded and low-frequency, but it means
metering is best-effort, not exact.

Fix — **LARGE/defer (human):** move to the transactional store the README plans and
record usage as it streams (or persist synchronously on `done()`), so a crash can't
drop already-incurred cost.

---

## 7. INFO — Incoming caller number is attacker-controllable and stored verbatim
**File:** `crates/postern-telephony/src/voice.rs:107-116`; `src/sms.rs:97-104, 128-134`

Caller-ID / SMS sender numbers come from the carrier (`call.number()`,
`sms.number()`) and are trivially spoofable over SS7/CLI — the crate stores them
verbatim into the encrypted call/SMS log with no "unverified" marker. This is
**correctly disclosed** at the transport level (spec §5 lists SS7 spoofing; crate
honesty note), so it is not a code defect — flagged only so the future call-log UI
never renders a stored number as an authenticated identity.

Fix — **SMALL/safe (apply now):** none required in the crate; note it as a UI
requirement (don't imply the number is verified).

---

## What holds up (verified, worth stating)

- **No false E2EE / no covert exfiltration.** The telephony crate never touches
  RTP/SRTP media — audio stays on the modem/carrier and callaudiod (`audio.rs` only
  switches a UCM mode). The code repeatedly and accurately states carrier SMS/voice is
  **not** private on the wire (lib.rs:37-44, sms.rs:9-11, voice.rs:12-15, spec §5).
  No "encrypted/private call" overclaim anywhere.
- **Sealed store crypto is sound and honest.** XChaCha20-Poly1305 via `postern-core`,
  `nonce‖ciphertext`, Argon2id KDF (store.rs), with tests asserting no-plaintext-leak,
  wrong-key/tamper rejection, and truncation-never-panics (types.rs:245-259). Untrusted
  wire bytes are parsed defensively (length checks before every slice; the one
  `try_into().unwrap()` at store.rs:113 is provably in-bounds and only runs on
  already-AEAD-verified plaintext).
- **Proxy honestly labels the privacy boundary.** The subscription tier is described,
  in code comments (proxy.mjs:19-34), the README (:22-41), and the client Privacy panel
  (client/index.html Privacy ledger) as a **trust-reduction, not trust-elimination**
  design: the proxy sees plaintext in memory, is an "extra party," and the "no extra
  parties" claim is explicitly scoped to Sovereign only. Prompt text is never logged or
  persisted — logs and the JSON store carry token **counts** only (verified:
  proxy.mjs:256-259, :474-475, :151-156, :693-694). BYO-Claude-key (Sovereign) is
  labeled the most-private, recommended tier and is never removed/degraded.
- **No revenue touches the token.** Subscription revenue is flat fiat via Stripe billed
  against the operator's Anthropic contract; no crypto/token accounting anywhere in the
  billing path — consistent with the "revenue is corporate, never the token" posture.
- **Stripe webhook verification is correct:** raw-payload HMAC-SHA-256, timing-safe
  compare, 5-min tolerance (proxy.mjs:283-301), with reject cases unit-tested
  (metering-check.mjs:90-97).
