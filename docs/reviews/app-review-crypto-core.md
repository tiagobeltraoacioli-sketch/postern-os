# Security review — Crypto Core & Sealing

**Slice:** `postern-core`, `postern-keys`, `postern-vault`, `postern-seal-companion`
**Reviewer:** fable5 security+technology pass · 2026-07-10 · code READ-ONLY
**Status context:** products are pre-release and **UNAUDITED** (README banner present and accurate). Nothing below is a certification. No crate in this slice touches revenue or the token — the "personal products free / no revenue on token" guardrail is upheld.

Findings are ranked most-severe first. Each has: severity · location · concrete failure · minimal fix, marked **SMALL/safe (apply now)** or **LARGE/defer (human)**.

---

## F1 · HIGH — Unpinned peer-verify accepts any self-signed report as `Genuine`

**Where:** `crates/postern-seal-companion/src/lib.rs:51` (`trusted_pubkey: Option<Vec<u8>>`), `lib.rs:75-97` (`verify_report`), `lib.rs:56-58` (`Verdict::Genuine` doc).

**Failure (inputs → bad outcome):** when `Expected.trusted_pubkey` is `None`, the signature at `lib.rs:93` is verified against `report.pubkey` — a field the *attacker supplies inside the report*. An attacker device can: generate its own Falcon‖ML-DSA keypair, copy the published `os_roothash`, echo the verifier's fresh nonce, sign the transcript with its own key → `Verdict::Genuine` ("a genuine, unmodified Postern build", `lib.rs:57`). There is no chain from the report key to any root of trust anywhere in this code; the crate doc (`lib.rs:18-19`) says mobile attestation "chains to the vendor/Google CA", but no chain check exists. In unpinned mode the verdict proves only "someone holds a keypair and saw the challenge" — the roothash and measurement fields are attacker-chosen strings, not attested facts.

**Fix:**
- **SMALL/safe (apply now):** make the honest semantics unmissable in the type: either require `trusted_pubkey` (drop the `Option`), or return a distinct verdict for the unpinned path (e.g. `Verdict::SignedButUnpinned`) and rewrite the `Verdict::Genuine` docstring so it never claims "genuine build" without a trust root. Also fix the field doc at `lib.rs:50` ("accept any key that signs validly" reads as a feature; it is a trust-nothing mode).
- **LARGE/defer (human):** implement the actual trust chain (device key certified by a Postern/vendor CA, or TOFU pinning UX) before any peer-verify flow ships.

## F2 · MEDIUM — Canonical AEAD seal has no AAD / domain separation and no version byte

**Where:** `crates/postern-core/src/lib.rs:37-57` (`aead::seal` / `aead::open`); consumers at `crates/postern-vault/src/lib.rs:91,98`, `crates/postern-courier/src/lib.rs:107,139`, `crates/postern-telephony/src/store.rs:92,99`.

**Failure:** `seal(key, plaintext)` takes no associated data, and the wire format is bare `nonce ‖ ct` with no context or version. Consequences: (a) if a 32-byte key is ever shared or reused across contexts (vault key also used for a telephony store, a backup flow re-using the derived passphrase key, etc.), a sealed blob from one product opens verbatim in another — cross-protocol/confused-deputy substitution; (b) an attacker with filesystem access can swap two blobs sealed under the same key (e.g. an old vault snapshot for a new one) and the AEAD accepts both — no binding to purpose, filename, or version; (c) with no version byte, a future KDF/param bump (see F5) has no in-band signal, inviting downgrade-by-guessing logic in apps. Notably, the crate *does* do domain separation for the attestation transcript (`lib.rs:80-99`) and explains why — the same argument applies to the seal itself.

**Fix:**
- **SMALL/safe (apply now):** add `seal_with_aad(key, aad, plaintext)` / `open_with_aad(...)` beside the existing pair (RustCrypto `Aead::encrypt` already supports `Payload { msg, aad }`), and document per-product AAD strings (`"postern-vault/v1"`, `"postern-telephony/v1"`, …) for all *new* blobs. Existing API stays for already-sealed data.
- **LARGE/defer (human):** versioned wire format (`ver ‖ nonce ‖ ct`) with a migration story for previously sealed blobs; roll consumers onto AAD-bound sealing.

## F3 · MEDIUM — Derived vault key is a bare `Copy` array; SDK exports it into GC memory

**Where:** `crates/postern-core/src/lib.rs:125-134` (`kdf::derive_key -> [u8; 32]`); `crates/postern-vault/src/lib.rs:115-117`; `crates/postern-sdk/src/vault.rs:62-65` (out-of-slice but direct consumer).

**Failure:** `derive_key` returns `[u8; 32]`, which is `Copy` and not zeroized by the callee. Every implicit copy (moves into enums, closure captures, temporaries during `?` conversions) leaves master-key bytes on the stack with no wipe. The repo's own better pattern exists — `postern-courier` wraps its AEAD key in `Zeroizing` and documents why (`crates/postern-courier/src/lib.rs`, `shared_key`), and `postern-panic` has to remember to zeroize manually at three separate sites (`crates/postern-panic/src/lib.rs:59-60,76,82`) precisely because the type doesn't do it. Worse, the uniffi export `postern-sdk/src/vault.rs:62-65` returns the key as `Vec<u8>` across FFI into Kotlin/Swift, where GC copying makes zeroization impossible — the vault master key ends up in unmanageable managed-heap copies.

**Fix:**
- **SMALL/safe (apply now):** change `kdf::derive_key` (and the vault re-export) to return `zeroize::Zeroizing<[u8; 32]>`; call-site churn in this workspace is small and mechanical.
- **LARGE/defer (human):** redesign the SDK boundary so the passphrase goes *in* and only sealed blobs come *out* (derive + seal on the Rust side); never hand the raw key across FFI.

## F4 · MEDIUM — `Vault::seal` leaks secret copies via serialization realloc

**Where:** `crates/postern-vault/src/lib.rs:121-130` (`serialize`), used by `seal` at `lib.rs:89-94`.

**Failure:** `serialize` starts from `Vec::new()` and grows with `extend_from_slice`. Each reallocation copies everything written so far (i.e. earlier secrets) into a new heap block and frees the old one **without wiping it**. `seal` then zeroizes only the *final* buffer (`lib.rs:92`), so a vault with several entries predictably leaves plaintext secret fragments in freed heap memory. This directly undercuts the crate's stated property ("The plaintext serialization is zeroized before returning", `lib.rs:87-88`, and "Secrets are wiped from RAM on drop", `lib.rs:46`).

**Fix — SMALL/safe (apply now):** precompute the exact size (`Σ 8 + k.len() + v.len()`) and allocate once with `Vec::with_capacity` (the `aead::seal` output copy of the plaintext is fine — it's ciphertext by then). Same hygiene nit applies to `deserialize`'s intermediate copies, see F7.

## F5 · MEDIUM-LOW — Argon2id 19456/2/1: sane as a floor, low for an at-rest vault master key

**Where:** `crates/postern-core/src/lib.rs:119-121`.

**Assessment (question asked directly):** m=19 MiB, t=2, p=1 is exactly the OWASP minimum recommendation and the `argon2 0.5` defaults — *sane*, correctly Argon2id, correctly version 0x13, and pinning them explicitly against silent dependency-default drift (`lib.rs:113-118`) is genuinely good practice. But this is the *interactive login* tier; for an offline-attackable at-rest vault (the exact threat here: a stolen sealed blob brute-forced on GPUs), RFC 9106's second recommendation (m=64 MiB, t=3, p=4) or higher is the norm (cf. Bitwarden's Argon2 default 64 MiB/t=3). Salt <8 bytes is rejected by the argon2 crate (error path) so the `lib.rs:124` doc is enforced; note there is **no helper to generate a random salt**, and every in-repo example uses a static salt (tests only, but it's the pattern app authors will copy).

**Fix:**
- **SMALL/safe (apply now):** add a `pub fn generate_salt() -> [u8; 16]` (OsRng) next to `derive_key`, and a doc line stating the params are the OWASP interactive floor, to be raised with a format version before release.
- **LARGE/defer (human):** raise params for the vault at-rest tier and version the sealed-blob format (depends on F2's version byte).

## F6 · LOW — `deserialize` bounds checks can overflow on 32-bit targets

**Where:** `crates/postern-vault/src/lib.rs:141-156` (`i + klen > data.len()`, `i + vlen > data.len()`, and `i + 4` in `read_len` at `lib.rs:136`).

**Failure:** `klen`/`vlen` are attacker-length u32 values up to 2³²−1. On a 32-bit target (`usize` = u32), `i + klen` wraps, the bounds check passes, and `data[i..i + klen]` panics (slice end < start) — a DoS panic on malformed input. Reachability is limited: `deserialize` runs only on AEAD-authenticated plaintext (good design — auth-then-parse), so triggering it requires the vault key; this is defense-in-depth, not an exposed surface. Release builds on 64-bit are unaffected.

**Fix — SMALL/safe (apply now):** use `i.checked_add(klen).filter(|e| *e <= data.len())` (and same for the `+4`), returning `VaultError::Corrupt` on overflow.

## F7 · LOW — Corrupt-path secrets dropped un-zeroized in `deserialize`

**Where:** `crates/postern-vault/src/lib.rs:132-158`; caller `Vault::open` at `lib.rs:97-102`.

**Failure:** `Vault::open` carefully zeroizes `plain` before propagating errors (`lib.rs:98-101` — good), but if `deserialize` fails midway, the partially-filled `BTreeMap` `m` — which already holds copies of decrypted secrets (`lib.rs:154`) — is dropped without wiping. `Vault`'s `Drop` (`lib.rs:105-111`) never runs because no `Vault` was constructed. Same limited reachability as F6 (requires the key + a corrupt-but-authenticated blob).

**Fix — SMALL/safe (apply now):** on the error paths, iterate `m.values_mut().for_each(Zeroize::zeroize)` before returning (or build into a small guard struct whose `Drop` wipes).

## F8 · LOW — Silent `as u32` length truncation breaks a documented injectivity claim

**Where:** `crates/postern-core/src/lib.rs:95` (`m.len() as u32` in `attestation_transcript`); `crates/postern-vault/src/lib.rs:124,126` (`k.len()`/`v.len() as u32`).

**Failure:** for inputs ≥ 4 GiB the length prefix silently truncates. In the transcript this voids the injectivity property the doc explicitly claims (`lib.rs:72-73`): two distinct `(measurement, nonce)` inputs could encode to colliding signed bytes. In the vault it produces a blob that deserializes to different entries than were stored. Practically absurd sizes, but this is precisely a "comment asserts a property the code doesn't fully deliver."

**Fix — SMALL/safe (apply now):** `u32::try_from(len).expect(...)` is not acceptable on attacker-influenced input — return an error (transcript: change signature to `Result`, or `assert!` with a doc note since measurement is producer-side; vault: `VaultError::Corrupt` on oversize entry at `put`/serialize time).

## F9 · LOW — `aead::open` misclassifies structurally-invalid blobs as "wrong key"

**Where:** `crates/postern-core/src/lib.rs:50-52`.

**Failure:** minimum valid blob is `NONCE_LEN + 16` (Poly1305 tag), but the check is only `< NONCE_LEN`. A 24–39-byte blob returns `SealError::Open` ("wrong key or tampered") instead of `Corrupt`, giving apps a misleading signal (a UI might prompt "wrong passphrase?" for a truncated file). No confidentiality/integrity impact.

**Fix — SMALL/safe (apply now):** `if sealed.len() < NONCE_LEN + 16 { return Err(SealError::Corrupt); }` (add a `TAG_LEN` const).

## F10 · LOW — Passkey private key not bound to `rp_id`/`credential_id` at rest

**Where:** `crates/postern-keys/src/lib.rs:76-86` (`to_key_bytes` / `from_key_bytes`).

**Failure:** the vault stores only the raw 32 key bytes; `from_key_bytes` accepts any `rp_id`/`credential_id` with any key. A bug (or blob-swap inside the vault, cf. F2's lack of AAD) that pairs site A's key with site B's rp_id yields signed assertions under the wrong identity, and nothing cryptographically prevents it. Also note `to_key_bytes` returns a `Copy` array — honestly documented as caller-owned (`lib.rs:73-75`), but the same F3 argument favors `Zeroizing`.

**Fix:** **SMALL/safe (apply now):** document that the vault entry must be a single record `(rp_id, credential_id, key)` (e.g. length-prefixed) and add a constructor that parses it, rather than three loose values. **LARGE/defer (human):** AAD-bind passkey blobs once F2 lands.

## F11 · LOW — Confirm the cipher instance's internal key copy is wiped

**Where:** `crates/postern-core/src/lib.rs:38,54` (`XChaCha20Poly1305::new(key.into())`); `crates/postern-core/Cargo.toml:12`.

**Failure to rule out:** `XChaCha20Poly1305` holds its own copy of the 32-byte key for the life of the cipher object. Whether that copy is zeroized on drop depends on the `chacha20poly1305` crate's zeroize wiring for the resolved version/feature set — it is not asserted anywhere here, in contrast to `postern-keys`' excellent compile-time `ZeroizeOnDrop` assertion (`crates/postern-keys/src/lib.rs:43-46`).

**Fix — SMALL/safe (apply now):** add the same `const _:` ZeroizeOnDrop static assertion for `XChaCha20Poly1305` in `postern-core` (and enable the crate's `zeroize` feature explicitly if the assertion fails to compile).

## F12 · INFO / honesty check — crate-doc claims that live outside the code

- `crates/postern-vault/src/lib.rs:4-9`: "TEE-wrapped by StrongBox/Secure Enclave" and "the app hybrid-wraps the vault key with … ML-KEM so a harvested sealed blob is PQ-protected" — none of this exists in the crate; it is app-layer aspiration written in product-copy voice. Sealed-with-passphrase blobs today are protected by Argon2id + XChaCha20 only (which is fine — symmetric crypto is not the PQ weak point — but the sentence reads as a shipped property). **SMALL/safe:** reword to future tense / "the app layer is expected to…".
- `crates/postern-vault/src/lib.rs:46` "Secrets are wiped from RAM on drop" — true for `Drop`, undercut by F4/F7 copies; keep the claim only once those land. Entry *names* are never wiped (deliberate per `lib.rs:82`, but the blanket sentence overstates).
- Positives worth keeping: `postern-keys` honest-limits block (`lib.rs:12-16`), `postern-seal-companion` honest-limits block (`lib.rs:18-21`) except the `Verdict::Genuine` wording (F1), README's "pre-mainnet, audit-gated, unaudited" banner, and `SECURITY.md`'s explicit do-not-deploy stance — all consistent with the no-overclaim guardrail.

---

## What is solid (verified, not just absent-of-findings)

- **Nonce handling:** fresh 24-byte XChaCha20 nonce from `OsRng` per seal (`postern-core/src/lib.rs:39`) — random-nonce collision risk at 192 bits is negligible; no nonce-reuse path exists; nonce travels in-band and length is checked before `XNonce::from_slice` (no panic path, `lib.rs:50-55`).
- **Auth-then-parse:** vault deserialization only ever runs on AEAD-authenticated plaintext (`postern-vault/src/lib.rs:97-99`) — untrusted-blob parsing is not exposed.
- **KDF pinning rationale** (`postern-core/src/lib.rs:113-118`) and salt-length enforcement via the argon2 crate's error path.
- **Transcript design:** domain tag + length-prefixed variable field (`postern-core/src/lib.rs:80-99`) is the right construction (modulo F8's u32 edge).
- **Compile-time ZeroizeOnDrop assertion** in `postern-keys/src/lib.rs:43-46` — a pattern worth propagating (F11).
- **No secrets in `Debug`/errors:** `Credential` doesn't derive `Debug`; error enums carry no key/plaintext material; argon2 error strings contain parameter info only.
