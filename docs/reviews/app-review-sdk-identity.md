# Security + Technology Review — SDK, Identity & Onboarding

**Scope:** `crates/postern-sdk` (unified UniFFI surface), `apps/postern-login` (Chiave — wallet-as-login), `apps/postern-onboard` (Sarto — BYO-Claude-key onboarding + managed-device policy desk).
**Status of the code under review:** pre-release, UNAUDITED. Both apps are explicit browser stand-ins for the Rust/TEE product and label themselves as such throughout.
**Reviewer note on the ethos checks (verified, not assumed):** I searched for a covert monitoring path and did not find one — see finding P1. The BYO-key "less private with cloud Claude" boundary IS disclosed at onboarding. The pricing/ethos guardrails (no revenue in the token, personal products free) are not contradicted anywhere in this slice.

Findings ranked most-severe first.

---

## HIGH

### H1 — SDK: secret material crosses the FFI as plain Records/Strings; generated Kotlin `toString()`/Swift dumps will print mnemonics and secret keys
- **Where:**
  - `crates/postern-sdk/src/wallet.rs:59-67` — `NewWallet` is a `#[derive(uniffi::Record)]` with `pub mnemonic: String`.
  - `crates/postern-sdk/src/courier.rs:8-14, 27-30` — `Recipient` Record with `pub secret: Vec<u8>` (ML-KEM decapsulation key).
  - `crates/postern-sdk/src/keys.rs:56-60` — `Credential::to_key_bytes()` returns the raw P-256 private key as `Vec<u8>`.
- **Concrete failure:** UniFFI lowers Records into Kotlin `data class` / Swift `struct` values. Kotlin data classes auto-generate `toString()` including every field; any app-layer `Log.d("wallet", newWallet.toString())`, crash reporter breadcrumb, or debugger watch prints the **BIP39 mnemonic** (the only backup — total wallet compromise) or the **courier secret key** into logcat/analytics. Foreign strings/arrays are GC-managed and cannot be zeroized; the mnemonic will linger in the JVM heap indefinitely. On the Rust side, the wrapper clones (`r.secret.clone()`, courier.rs:29) are not zeroized either — the core's `Drop for Recipient` wipes only the original.
- **Contrast:** the cores got this right (`postern-courier` zeroizes; `postern-keys` statically asserts `ZeroizeOnDrop`; `WalletCore` has zeroizing Drop). The SDK facade re-introduces the exposure at the boundary.
- **Fix:**
  - **SMALL/safe (apply now):** doc-comment every secret-bearing field/return with an explicit "never log; treat as toxic" warning, and zeroize the Rust-side intermediate clones before drop (wrap in `zeroize::Zeroizing` in `generate_recipient` / `generate_wallet`).
  - **LARGE/defer (human):** redesign the surface so secrets stay behind `Arc<Object>` handles (as `Credential` and `Wallet` already do): `generate_wallet` should return a `Wallet` object plus a one-shot `reveal_mnemonic()` method; `Recipient` should be an object whose secret never crosses as a Record field. This is a **wire-stability decision — cheaper before v0.1 ships bindings than after.**

### H2 — Sarto: the Anthropic API key is plaintext-at-rest in localStorage **by default**, and persisted on every keystroke
- **Where:** `apps/postern-onboard/index.html:1539` (`LS.KEY: "sarto.apiKey"`), `:2532-2533` (`el.apiKey.addEventListener("input", () => setKey(...))` writes to localStorage per keystroke), `:1929-1936` (`getKey`/`setKey`).
- **Concrete failure:** any other code with access to the browser profile — an extension, another same-origin page, a person at the unlocked machine, filesystem access to the profile's `Local Storage` sqlite — reads the billing credential. The opt-in "lock key" seal (`KeySeal`, :1561-1610) is good work (PBKDF2-310k → non-extractable AES-GCM, AAD-bound, fresh IV, all-or-nothing unlock), but it is **opt-in**, so the secure path is the one users won't take. The per-keystroke `input` listener also persists every partial key prefix.
- **Honesty check: PASSES.** The insecure default is disclosed in plain sight (`:1038-1040`: "Without a lock, the key sits readable in this browser's localStorage — any code or person with access to this browser profile can read it") — this is an honest insecure default, not a hidden one. Still an insecure default.
- **Fix:**
  - **SMALL/safe (apply now):** persist only on `change`, not `input`; and when a key is first saved unsealed, surface a one-time inline prompt to set the lock passphrase.
  - **LARGE/defer (human):** make sealed-at-rest the only persistent mode (unsealed key lives in `sessionStorage`/memory only). UX decision — the "works with zero friction" property is currently deliberate.

---

## MEDIUM

### M1 — SDK: `Mutex::lock().unwrap()` — lock poisoning panics across the FFI boundary
- **Where:** `crates/postern-sdk/src/vault.rs:34,39,44,49,55`; `crates/postern-sdk/src/panic.rs:30,35,41,46,51`.
- **Concrete failure:** if any core method panics while the lock is held (e.g. a bug in `postern_vault::put`), the mutex is poisoned and **every subsequent call on that object panics**. A Rust panic crossing UniFFI aborts the process on mobile — for `PanicSession` specifically, this turns a recoverable state into an app crash **during a duress scenario**, the worst possible time.
- **Fix — SMALL/safe (apply now):** `self.inner.lock().unwrap_or_else(|p| p.into_inner())` (the cores' data is a plain map; poisoned state is safe to recover), or map to `PosternError`. Ten call sites, mechanical.

### M2 — Sarto: managed-policy time windows that cross midnight silently never block
- **Where:** `apps/postern-onboard/index.html:1510-1512` — `if (w.days.includes(t.getDay()) && hm >= w.start && hm < w.end ...)`; window normalization at `:1396-1402` accepts any `HH:MM` pair.
- **Concrete failure:** a parent sets "Bedtime, 21:00–06:00, blocks video/games". `hm >= "21:00" && hm < "06:00"` is unsatisfiable, so the window **never matches**: the policy panel truthfully displays a limit that the enforcement check never enforces. That is a transparency product showing the managed user (and the admin) a limit that does not exist — an integrity failure of exactly the property Sarto sells. Also `end < start` on the same day never matches; `checkSite` is the stated reference for the OS enforcement layer, so the bug propagates by copy.
- **Fix — SMALL/safe (apply now):** in `checkSite`, treat `end <= start` as an overnight window (`hm >= start || hm < end`, with day-of-week attribution for the pre-midnight day); or reject `end <= start` in `normalizeLimits` with a visible error.

### M3 — Chiave/Sarto: KDF iteration count is read from the attacker-writable blob with no floor
- **Where:** `apps/postern-login/index.html:1077` — `PID.passKey(pass, salt, blob.kdf.iter)`; `apps/postern-onboard/index.html:1254-1256` — `openBlob` uses `blob.kdf.iter`.
- **Concrete failure:** anything that can write localStorage (extension, same-origin XSS) can rewrite `kdf.iter` to `1`. The GCM tag fails, so decryption breaks — but the **next legitimate unlock attempt runs PBKDF2 with 1 iteration over the victim's real passphrase**, and a subsequently planted observer (or the KDF-downgrade + re-seal combination) gets an essentially unhardened passphrase check. Classic KDF-parameter-downgrade shape; costs one line to close.
- **Fix — SMALL/safe (apply now):** `const iter = Math.max(blob.kdf.iter | 0, KDF_ITER)` before deriving, in both files.

### M4 — Chiave: seed + PKCS#8 private key are kept in JS memory for the entire session when only derived handles are needed
- **Where:** `apps/postern-login/index.html:1095-1103` — `session = { payload, signer, fpr, vaultKey }` where `payload = { seed, alg, priv, pub }`; `payload.priv` is re-used only at `:1298-1299` (biometric enrollment).
- **Concrete failure:** after `importSigner` (non-extractable CryptoKey) and `vaultKey` derivation, the hex seed and base64 PKCS#8 private key remain reachable via `window.session` equivalents for the whole session — a larger XSS/devtools/heap-snapshot surface than necessary. The page honestly states a browser can't zeroize (:664-668), but it can still *drop references early*.
- **Fix — SMALL/safe (apply now):** after `startSession` builds `signer`/`vaultKey`, null out `payload.seed`; keep `payload.priv` only if biometric enrollment is still possible (or re-prompt the passphrase for enrollment instead — one extra prompt, much smaller residency window).

### M5 — Chiave: the challenge-response demonstrates signing, not replay/phishing resistance — and grants the session before verifying
- **Where:** `apps/postern-login/index.html:834-844` (`makeChallenge` — origin is the string `"chiave-demo"`, `challengeBytes` = `JSON.stringify` relying on insertion order), `:1114-1130` (`signFreshChallenge` — verification result only paints `verifyLine`; `startSession` at `:1095` already granted the session), `:1104-1109`.
- **Concrete failure (as a *reference flow*, which is what Chiave claims to be):
  1. the verifier never checks `nonce` freshness/single-use, `issued` expiry, or that `origin` equals the actual RP origin — a captured `{challenge, sig}` pair verifies forever (replay), and a phishing origin can proxy challenges (no origin binding is *enforced*, only *carried*);
  2. canonicalization by insertion order breaks the moment a real RP reconstructs the object (Sarto already ships `stableStringify` at onboard/index.html:1214-1218 — the two reference apps disagree);
  3. session state flips to "signed in" before the verify call returns, so the check is decorative even in-page.
- Locally this is harmless (signer and verifier are the same tab). It becomes a bug when someone implements the server side from this reference.
- **Fix:** **SMALL/safe (apply now):** use `stableStringify`-style canonical bytes, check `origin`/expiry in the demo verifier, and order `verify → show session`. **LARGE/defer (human):** the design of record (`docs/specs/POSTERN-IDENTITY.md`) must pin nonce single-use, audience binding, and canonical encoding before any RP implementation exists.

### M6 — Chiave: wallet blob public `meta` (enrolled pubkey, alg, fingerprint) is not authenticated
- **Where:** `apps/postern-login/index.html:1028-1033` — `meta: { alg, pub, fpr, created }` stored plaintext; AAD at `:870` is the constant `"postern.login.v1"` only; `:1121-1123` verifies challenges against `blob.meta.pub`.
- **Concrete failure:** localStorage writer swaps `meta.pub`/`meta.fpr` → the locked screen displays an attacker-chosen fingerprint (`:940-944`) and challenge verification runs against the swapped key. Silent identity-display tampering in an identity product; the sealed payload itself is intact so nothing detects the swap.
- **Fix — SMALL/safe (apply now):** include the serialized `meta` in the AES-GCM `additionalData` (AAD) so any meta tamper fails the tag at unlock. Same pattern applies to Sarto's `sealBlob` meta (`apps/postern-onboard/index.html:1243-1253`) — there the damage is caught later by post-install policy verification (:2436-2437), so it is Low there.

---

## LOW

### L1 — SDK: `PosternError` is a single string variant — no programmatic error discrimination, and messages become wire format
- **Where:** `crates/postern-sdk/src/error.rs:9-13`; every wrapper's `map_err(|e| PosternError::from(e.to_string()))`.
- **Failure:** app layers will inevitably match on message substrings ("must be 32 bytes", "decrypt") to distinguish wrong-key from corrupt-data from bad-length; those strings then become un-evolvable wire format. Also `wallet.rs:103-105` funnels `serde_json` errors verbatim, which can echo fragments of caller params into error UI/logs.
- **Fix — LARGE/defer (human):** add coarse typed variants (`InvalidLength`, `CryptoFailure`, `Locked`, `Parse`) before bindings ship; string-only is fine for v0.1 *only if* v0.2 is allowed to break the error enum.

### L2 — SDK: `verify_assertion` returns `Result<bool, PosternError>` — two distinguishable "not verified" paths
- **Where:** `crates/postern-sdk/src/keys.rs:70-84`.
- **Failure:** malformed hash length → `Err`, bad signature → `Ok(false)`. Callers that only `try/catch` and ignore the boolean treat a forged signature as success. Boolean-returning verify is a classic misuse-prone shape.
- **Fix — SMALL/safe (apply now):** document loudly; or (LARGE, API break) return `Verdict`-style enum / make failure an error.

### L3 — Both apps: `store.set` swallows write failures (quota, private-mode) silently
- **Where:** `apps/postern-login/index.html:874-877`; `apps/postern-onboard/index.html:1548-1552`; worst case `postern-login/index.html:1028` — "Wallet created and sealed" is announced even if the localStorage write threw, and Sarto's `KeySeal.lock` (`:2574`) deletes the plaintext key after a `persist()` whose failure is swallowed → key silently gone at next launch.
- **Fix — SMALL/safe (apply now):** have `store.set` return success; check it at the three seal/persist call sites and surface an error instead of the success message.

### L4 — Sarto: transparency floor check verifies only 2 of 4 declared constants
- **Where:** `apps/postern-onboard/index.html:1454-1455` — `verifyPolicy` refuses on `visible_to_managed_user !== true || monitoring !== "none"` but does not check `data_collected` / `covert_mode`, which `buildPolicy` (:1426-1433) declares part of the ethical floor.
- **Failure:** a hand-crafted signed policy (admin signs arbitrary JSON out-of-band) with `data_collected: "browsing"` would pass the floor check and render as verified. The plain-language renderer wouldn't show the field — so the panel under-reports relative to the payload. Purely defensive today (no code consumes those fields), but the floor should be checked in full.
- **Fix — SMALL/safe (apply now):** extend the refusal condition to all four constants.

### L5 — Chiave: login rate-limit delay is cosmetic; offline brute force is the real bound (labeled)
- **Where:** `apps/postern-login/index.html:1083-1088`.
- **Failure:** the delay runs *after* the error renders, client-side only; the ciphertext is exfiltratable and PBKDF2-SHA-256/310k is weak against GPU guessing versus the product's Argon2id. **The page labels this stand-in honestly** (:474-476, :655). No action beyond keeping the label; noting for completeness.

### L6 — Chiave: `unhex` throws on empty/odd-length input
- **Where:** `apps/postern-login/index.html:696` — `s.match(/.{2}/g)` returns `null` → TypeError in `startSession` if a (corrupt) payload has an empty seed. Caught by the surrounding try only on the passphrase path, not the biometric path (:1272-1273 catch does cover it — message is just unfriendly). **SMALL/safe:** guard and throw a typed message.

---

## ETHOS / HONESTY VERIFICATION (checked, passing)

- **No covert surveillance path — VERIFIED (P1).** In Sarto: the managed banner renders unconditionally whenever a policy exists (`renderBanner`, onboard/index.html:1733-1746 — no view/flag condition); `buildPolicy` hard-codes the transparency constants (:1426-1433); `verifyPolicy` refuses non-transparent policies (:1454-1455, see L4 for the gap); the admin is named + fingerprinted inside the signed payload; the policy is stored plaintext *on purpose* so its subject can read it (:1545). The system prompt (:1951) instructs the model to refuse concealment help. **No hidden monitoring, logging, or reporting code path exists in this file.** The only network destination is `api.anthropic.com`, enforced by CSP `connect-src` (:5).
- **BYO-key "less private" boundary — DISCLOSED at onboarding.** Privacy dialog rows (:1070-1082) state plainly that configurator text goes to Anthropic under the user's key and voice goes to the browser vendor, with the fully-local manual path offered as the equivalent alternative (:1106-1109); the composer footer and status line repeat it. Chiave's CSP is `connect-src 'none'` (login/index.html:5) — its zero-network claim is enforced, not just asserted.
- **WebAuthn PRF used correctly (login/index.html:1189-1279):** platform authenticator + `userVerification: "required"`, PRF evaluated on an assertion (not create), fixed domain-separated PRF input, wrap key = SHA-256(prf ‖ tag), sealed second copy AAD-bound, honest hard-fail when PRF is unsupported ("no fake gate", :1239) rather than a theatrical biometric. Panic Lock deletes the biometric-sealed copy (:1140-1141) so a coerced finger opens nothing — matches the stated design.
- **Model-tool input validation (onboard):** `set_profile` output passes through `normalizeProfile` (:1359-1377) — app-id whitelist, boolean/enum coercion, length clamps — and can only write to the review panel (`runTool`, :2022-2028), never apply. Prompt-injection blast radius is a pre-filled form the user must confirm. Good.
- **Stand-in labeling:** every weakened primitive (PBKDF2 vs Argon2id, Ed25519 vs Falcon‖ML-DSA, 184-bit demo wordlist vs BIP39-256) is labeled at point of use and in the honesty dialogs in both apps.

## Panic/unwrap summary
- SDK: only the ten mutex `.unwrap()`s (M1); all byte-length inputs validated via `to_array` (lib.rs:40-44) with typed errors — good.
- Apps: no unhandled-rejection foot-guns found beyond L6; all `innerHTML` sinks reviewed use `escapeHtml` on dynamic values (both files ship an identical correct escaper).

---

*Reviewed 2026-07-10 · read-only review · no code modified.*
