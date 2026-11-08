# Security + Technology Review — PQ Messaging & Tor Transport

**Scope:** `crates/postern-courier`, `crates/postern-messenger`, `crates/postern-tor` (every `.rs` read), plus the `postern-core::aead` seal courier depends on and the locked versions of `ml-kem 0.2.3`, `vodozemac 0.8.1`, `arti-client 0.28.0`.

**Status context:** all three crates are pre-release and UNAUDITED, as is the RustCrypto `ml-kem` crate itself (pre-1.0, no independent audit). Nothing below is a claim that the products are safe to ship; findings are ranked most-severe first.

---

## F1 · HIGH — The "ephemeral Tor onion service" transport does not exist; the headline claim rides on unshipped code

- **Where:** `crates/postern-courier/src/lib.rs:4-5, 21-22` ("Send a file/message … over an ephemeral Tor onion service (`postern-tor` hosts it)"; "Hosting the live onion service is `postern-tor` on-device"); `crates/postern-courier/Cargo.toml:5` ("…file drop over an ephemeral Tor onion service…"); `crates/postern-tor/Cargo.toml:14`; `crates/postern-tor/src/lib.rs` (entire file).
- **Failure:** `postern-tor` is compiled with the `onion-service-client` feature only — it can *connect to* onion services, but there is no `onion-service-service` feature, no hosting API, no ephemeral-onion lifecycle (create/publish/expire), and no code anywhere that transmits a `SealedPayload` over anything. The courier crate is a seal/open pair with no transport. A reader of the docs (and the README table at `README.md:47`) concludes the P2P drop works end-to-end today; it does not. Every downstream property claimed of the transport — ephemerality, "no server, no account", sender-online semantics, circuit behavior, replay handling — is unreviewable because it is unwritten.
- **Fix (two parts):**
  - **SMALL/safe (apply now):** amend the courier and README wording to "the crypto seal for the planned onion-service drop; hosting/transport is not yet implemented" so the doc matches the code.
  - **LARGE/defer (human):** implement the hosting path (arti `onion-service-service`), define the wire protocol (framing, size cap, one-shot semantics, address hand-off), then re-review it — the transport is where replay, downgrade, and DoS will actually live.

## F2 · HIGH — `json_rpc` reads an unbounded response with no timeout: trivial memory-exhaustion / hang DoS by a hostile peer

- **Where:** `crates/postern-tor/src/lib.rs:128-129` (`let mut raw = Vec::new(); stream.read_to_end(&mut raw)`), and no timeout anywhere in `json_rpc` (lib.rs:108-134) or `connect` (lib.rs:81-90).
- **Failure:** inputs → bad outcome: a malicious or compromised RPC node / onion service (or an active exit on the plain-HTTP path, see F5) streams gigabytes, or simply never sends `\r\n\r\n` and never closes. Outcome: the client allocates until OOM, or the wallet/messenger task hangs forever — `Connection: close` (lib.rs:36-37, 44) makes stream-end *entirely the server's choice*. This is the RPC path "the wallet" uses per the module doc (lib.rs:5-6), so one hostile node stalls or kills the wallet.
- **Fix — SMALL/safe (apply now):** wrap the whole exchange in `tokio::time::timeout`, and read with a hard cap (e.g. `stream.take(MAX_RPC_RESPONSE)` with `MAX_RPC_RESPONSE` ≈ 1–4 MiB, erroring — not truncating silently — at the limit).

## F3 · HIGH — "Hybrid-encrypted" is an overclaim: the courier seal is pure PQ (KEM-DEM), with no classical KEM component

- **Where:** `crates/postern-courier/src/lib.rs:5-7` ("the payload **hybrid-encrypted** end-to-end: **ML-KEM-1024** … and **XChaCha20-Poly1305** encrypts the bytes under it").
- **Failure:** in post-quantum practice "hybrid" means classical KEM + PQ KEM combined (e.g. X25519 + ML-KEM-1024, as in X-Wing / TLS hybrid groups), so that a break or implementation flaw in the *new, less-battle-tested* ML-KEM code does not immediately expose plaintext. What the code does (lib.rs:91-108) is KEM-DEM: ML-KEM alone establishes the key; XChaCha20-Poly1305 is the DEM, not a second key-establishment leg. Inputs → bad outcome: an ML-KEM implementation bug (the crate is pre-1.0 and unaudited) or future cryptanalytic surprise leaves the payload with **no** security floor — the exact failure mode hybrids exist to prevent. Calling it "hybrid" claims a defense-in-depth property the wire format does not have.
- **Fix:**
  - **SMALL/safe (apply now):** reword to "PQ-sealed (ML-KEM-1024 KEM + XChaCha20-Poly1305 DEM); NOT a classical+PQ hybrid" and note the single point of failure.
  - **LARGE/defer (human):** adopt a real hybrid (X25519 + ML-KEM-1024, combiner per X-Wing) before any deployed payloads exist — the crate itself says wire breaks are still free pre-mainnet (lib.rs:11-14), so now is the cheap moment.

## F4 · MEDIUM — No authentication of the recipient public key or the sender: MITM on key exchange and payload forgery are out of scope but undocumented as *unsolved*

- **Where:** `crates/postern-courier/src/lib.rs:53` ("public key is shared out-of-band with senders"), lib.rs:89-108 (`seal` takes raw `recipient_public: &[u8]`), lib.rs:120 (`open` gives no sender identity).
- **Failure:** inputs → bad outcome: (a) the "out-of-band" channel for the ML-KEM public key is unspecified and there is no fingerprint/short-auth-string helper — if the key rides any interceptable channel, an active MITM substitutes their own key, decrypts, re-seals to the real key, and reads everything; the PQ seal is then decoration. (b) `seal` is sender-anonymous: anyone holding the recipient's public key can produce a valid `SealedPayload`, and `open` succeeding proves nothing about *who* sealed it — a MITM on the (future) transport can wholesale replace the payload with their own and the recipient cannot tell. The honest-limits paragraph (lib.rs:22-25) covers metadata but is silent on both of these.
- **Fix:**
  - **SMALL/safe (apply now):** document both gaps in the honest-limits paragraph ("key authenticity must be verified out-of-band — compare fingerprints; the seal does not authenticate the sender"), and add a helper that renders a short hash fingerprint of a public key for humans to compare.
  - **LARGE/defer (human):** decide the authentication story (sender signature over `kem_ct ‖ body` with a PQ signature, and/or PAKE-style word-code as magic-wormhole does) before the transport ships.

## F5 · MEDIUM — Plain-HTTP JSON-RPC through an exit relay is active-MITM-able; the doc frames only the anonymity benefit

- **Where:** `crates/postern-tor/src/lib.rs:98-107` (doc: onion "or a plain-HTTP RPC reached anonymously"; "an `https://` clearnet node over Tor would need a TLS layer").
- **Failure:** inputs → bad outcome: for a non-`.onion` host the exit relay sees and can **rewrite** the cleartext JSON-RPC in both directions — lie about chain state, swap destination addresses in responses, censor selectively. The doc presents the clearnet-HTTP path as a supported mode and notes only the missing-TLS limitation in passing; it never states that the exit is an active adversary in that mode. For a *wallet* RPC this is integrity-critical, not just privacy.
- **Fix — SMALL/safe (apply now):** state the exit-MITM risk explicitly in the `json_rpc` doc and prefer refusing (or requiring an explicit opt-in flag for) non-`.onion` hosts in `json_rpc`; the privacy-native onion path is already the stated default. LARGE/defer: add a TLS layer for clearnet hosts if that mode must exist.

## F6 · MEDIUM — Messenger `decrypt` discards `message_index`: Megolm replay attacks are undetectable by callers

- **Where:** `crates/postern-messenger/src/lib.rs:73-77` (`Ok(out.plaintext)` — the `message_index` field of vodozemac's `DecryptedMessage` is dropped).
- **Failure:** vodozemac's own doc on the discarded field (`vodozemac-0.8.1/src/megolm/inbound_group_session.rs:104-106`): "The message index, used to detect replay attacks." Inputs → bad outcome: a malicious homeserver (exactly the adversary the crate's own threat model names at lib.rs:13-15) re-delivers an old ciphertext; `decrypt` happily returns the old plaintext again with no signal, so the app cannot dedupe on `(session_id, message_index)` — replayed "send 1 BTC"-class messages appear as fresh. Matrix clients are *required* to track this index; the wrapper makes that impossible.
- **Fix — SMALL/safe (apply now):** return `(Vec<u8>, u32)` (or a small struct) from `decrypt` and document that callers MUST reject a repeated `(session_id, message_index)`. Pre-release, so the API break is free.

## F7 · MEDIUM — Raw KEM shared secret used directly as the AEAD key; no KDF, no binding of `kem_ct` to the body

- **Where:** `crates/postern-courier/src/lib.rs:100, 107` (`shared_key(shared.as_slice())` → `postern_core::aead::seal(&key, plaintext)`); `SealedPayload` at lib.rs:82-87 (two independent fields, no AAD).
- **Failure:** two distinct issues. (a) No KDF/domain separation: the 32-byte ML-KEM shared secret is used verbatim as the XChaCha20-Poly1305 key. It is uniform, so this is not exploitable today, but any future second use of the same secret (a MAC key, a session key) silently becomes key reuse across contexts. (b) Non-binding: the AEAD does not authenticate `kem_ct` (no AAD, no transcript), and ML-KEM is known not to provide the strongest ciphertext-binding properties (not MAL-BIND-K-CT). A protocol later composed on top (multi-recipient, re-wrapping, store-and-forward) can be broken by mix-and-match of `kem_ct`/`body` pairs in ways a bound design is immune to.
- **Fix — SMALL/safe (apply now, pre-wire-freeze):** derive the AEAD key as `HKDF-SHA-256(ikm = shared, info = "postern-courier/v1" ‖ H(kem_ct) ‖ H(recipient_public))` (or pass `kem_ct` as AAD to the seal — requires a small `postern-core::aead` AAD variant). This is exactly the kind of break lib.rs:11-14 says is still free.

## F8 · MEDIUM — One shared Tor client for wallet + messenger + container with no stream isolation: cross-product identity correlation

- **Where:** `crates/postern-tor/src/lib.rs:5-6` ("the wallet RPC, the messenger, and the container all talk to the network through one bootstrapped `PosternTor`"), lib.rs:53-58 (cheap-clone, pooled circuits), lib.rs:81-90 (`connect` sets no `StreamPrefs`/isolation).
- **Failure:** inputs → bad outcome: Arti reuses circuits across streams unless the caller sets isolation. Wallet RPC and messenger traffic from the same user can share a circuit (same exit, correlated timing), letting an exit or destination link "this wallet" with "this messenger account" — a metadata leak the products' privacy story does not admit. The `client()` escape hatch (lib.rs:94-96) exists but nothing steers products to use it.
- **Fix — SMALL/safe (apply now):** add an isolation token parameter (per product/identity) to `connect`/`json_rpc` mapping to Arti `StreamPrefs::set_isolation`, and document that distinct identities MUST pass distinct tokens. LARGE/defer: per-identity `TorClient::isolated_client()` handles.

## F9 · LOW — `ml-kem 0.2.3` skips the FIPS-203 §7.2 encapsulation-key input check; and the crate is unaudited

- **Where:** `crates/postern-courier/src/lib.rs:92-96` (comment claims "the fixed-size array conversion is the length check" — true, but that is the *only* check); `ml-kem-0.2.3/src/kem.rs:171-180` (`EncapsulationKey::from_bytes` is infallible — no modulus/round-trip check; the decapsulation-key path even carries an upstream `XXX` about not verifying `h`, kem.rs:56-58).
- **Failure:** FIPS 203 requires rejecting encapsulation keys whose coefficients are not canonical (ByteDecode₁₂ round-trip / modulus check) before Encaps. `seal()` will happily encapsulate to a non-canonical key. Direct impact is low (a malicious recipient key mostly hurts the payload sent *to* that attacker), but it is a FIPS-conformance gap in a crate whose doc leads with "FIPS-203", and it feeds interop/cross-implementation ambiguity. Separately: RustCrypto `ml-kem` is pre-1.0 and explicitly unaudited — worth stating next to "FIPS-203 (final)" in the courier docs.
- **Fix — SMALL/safe (apply now):** note both facts in the courier module doc; optionally add the canonical-encoding check in `seal()` (re-encode the decoded key and compare to input — constant cost, closes the gap without waiting on upstream). LARGE/defer: track upstream `ml-kem` 1.0/audit.

## F10 · LOW — CRLF injection into the hand-rolled HTTP request via `host`/`path`

- **Where:** `crates/postern-tor/src/lib.rs:38-51` (`build_rpc_request` interpolates `host` and `path` into the request head unvalidated).
- **Failure:** inputs → bad outcome: if a host or path ever derives from pasted/user input (`"x.onion\r\nX-Evil: 1"`, a path with a space or CR), the attacker injects headers or splits the request. Today's callers pass constants, but this is a public crate API.
- **Fix — SMALL/safe (apply now):** reject `host`/`path` containing whitespace/control bytes (`\r`, `\n`, space, `\0`) with a `TorError::Rpc` before formatting.

## F11 · LOW — HTTP response handling: no status-line check, no chunked-encoding support, doc mismatch

- **Where:** `crates/postern-tor/src/lib.rs:130-133`.
- **Failure:** the parser takes everything after the first `\r\n\r\n` as the JSON body. A `Transfer-Encoding: chunked` response (legal even with `Connection: close`) puts chunk-size lines in the "body" and the parse fails confusingly; a 4xx/5xx or redirect status is never surfaced as such; and the doc (lib.rs:102) says it "returns the parsed JSON `result`/error object" when it actually returns the whole JSON-RPC envelope.
- **Fix — SMALL/safe (apply now):** check the status line starts `HTTP/1.1 200`, error on `Transfer-Encoding: chunked` (or de-chunk), and fix the doc sentence. (This composes with the F2 cap/timeout change.)

## F12 · LOW — Courier hygiene nits: headline "yields nothing", no wire version byte, whole-file-in-RAM, early-return zeroize gap

- **Where:** `crates/postern-courier/src/lib.rs:18-19` and `Cargo.toml:5` ("a recorded circuit yields **nothing**"); lib.rs:82-87 (`SealedPayload` has no version/format byte); lib.rs:91, 120 (`&[u8]` plaintext / `Vec<u8>` out — a "file drop" holds the whole file in memory at least twice); lib.rs:100-103 and 135-137 (if `shared_key` errored, the early `?` return would skip `shared.zeroize()` — unreachable today since the KEM secret is exactly 32 bytes, but fragile under refactor).
- **Failure/honesty:** the honest-limits paragraph (lib.rs:22-25) *does* state the classical onion-address crypto, sender-online requirement, and timing/volume analysis — good. But the headline "yields nothing" contradicts it: a recorded circuit yields exact payload **size** (AEAD is length-revealing, no padding), timing, and direction. Docs should say "yields no plaintext, ever". The missing version byte means the *next* deliberate wire break (e.g. F3/F7 fixes) is undetectable at parse time.
- **Fix — SMALL/safe (apply now):** reword to "yields no payload plaintext (size/timing still visible)"; add a leading version byte to `SealedPayload` serialization while breaks are free; move `shared.zeroize()` into a scope guard or `Zeroizing` wrapper. LARGE/defer: streaming/chunked seal for large files; optional padding buckets.

## F13 · LOW — Messenger: exported session key is un-zeroized `String`; Olm distribution referenced but absent

- **Where:** `crates/postern-messenger/src/lib.rs:50-52` (`session_key()` → plain `String`), lib.rs:67-69 (`from_session_key(&str)`); lib.rs:32-33 and 66 claim the key is "shared out-of-band (Olm-encrypted per recipient device)" but no Olm code exists in the crate or callers.
- **Failure:** the Megolm session key — which decrypts the whole room history from that ratchet point — lingers in heap `String`s with no zeroization on either side. And the Olm-encrypted distribution the docs describe is aspirational; today the crate offers no safe way to move the key. (Credit: the classical-not-PQ and homeserver-metadata limits at lib.rs:9-15 are stated honestly — no overclaim there.)
- **Fix — SMALL/safe (apply now):** return `Zeroizing<String>` from `session_key()` and take the same in `from_session_key`; mark the Olm-distribution sentence as "planned (matrix-rust-sdk layer), not implemented here".

---

## Honesty scorecard (what the docs get right vs. overclaim)

| Claim | Verdict |
|---|---|
| Courier: sender-must-be-online, classical onion address, timing/volume analysis possible (lib.rs:22-25) | Honestly stated |
| Courier: "recorded circuit yields **nothing**" (lib.rs:19, Cargo.toml:5) | Overclaim — nothing *of the plaintext*; size/timing/endpoints leak (F12) |
| Courier: "hybrid-encrypted" (lib.rs:5) | Overclaim — pure PQ KEM-DEM, no classical leg (F3) |
| Courier: "ephemeral Tor onion service (`postern-tor` hosts it)" (lib.rs:4-5) | Overclaim — hosting unimplemented (F1) |
| Messenger: "Megolm is classical, HNDL applies; homeserver sees social graph" (lib.rs:9-15) | Honestly stated |
| Tor: bootstrap not exercised in CI, compile-only verification (lib.rs:17-19) | Honestly stated |
| Tor: plain-HTTP RPC "reached anonymously" (lib.rs:100) | Incomplete — exit can actively rewrite responses (F5) |

*Reviewed 2026-07-10. Read-only review; no code modified. All findings against pre-release, unaudited code — none of the SMALL fixes above constitute an audit.*
