<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# postern-signer-protocol

Phone-as-signer, desktop-as-terminal (**v1**). The **desktop requests** a
signature; the **phone** (which holds the hybrid **Falcon‖ML-DSA** wallet key)
**parses the actual bytes to be signed**, shows a human "what you see is what you
sign" sentence, and **approves + signs**. The private key never crosses the
channel — only signatures and approvals do — and that is enforced **structurally**
(the type system + a build-failing golden test), not by convention.

Implements Design §3 (phone-as-signer) and Security §4 (companion-signing) / §5.1
(the private-key denylist). Scoped to the v1 flow: signing a desktop
**wallet-login challenge** in the `postern-consiglio-auth` shape.
(`TransferIntent` proves the same shape generalises to value transfers.)

> ## ⚠️ SCAFFOLD — unaudited
> A compiling reference of the protocol shape, not a hardened, audited signer.
> The real signer is `mobile/core`'s `WalletCore`; `ScaffoldSigner` is a
> deterministic test stand-in and is **not real cryptography**. Standalone by
> design: it carries its own `[workspace]` and pulls no in-tree path/git deps, so
> `cargo build` / `cargo test` run without the rest of the monorepo.

---

## Shape

```text
Desktop (holds NOTHING)                 Phone (holds the key)
─────────────────────                   ─────────────────────
SignRequest{ session_id, req_nonce,  ─▶ replay guard: fresh nonce + monotonic
  counter, payload=encode(intent) }      counter + session binding (fail closed)
                                         decode payload from the ACTUAL bytes
                                         WYSIWYS: "this signs a login … can't
                                           move funds" (3 consequence tiers)
                                         human approves (or grant-covered tap)
                                         sign canonical digest; commit guard
  match & relay Approval          ◀──── Approval{ signature, public_key, digest }
```

## API surface

| Type / fn | Role |
|---|---|
| `DesktopRequester::{request_login, request, recv_approval}` | Terminal (no key): build a `SignRequest` with fresh nonce + monotonic counter, match the returned `Approval`. |
| `PhoneApprover::{receive, covered_by_grant, approve, decline}` | Custodian: run the replay guard (fail-closed), render WYSIWYS, sign the canonical digest, return only a signature. |
| `ReplayGuard::{check, commit, restore}` | Session/counter/nonce anti-replay; `restore` rebuilds it from a persisted watermark. |
| `resume::{seal_watermark, open_watermark}` | Authenticate + persist the anti-replay watermark so a phone restart cannot roll the counter back. |
| `ApprovalGrant` / `GrantScope` | Time-boxed, revocable single-tap auto-approval (never covers transfers). |
| `render` / `Wysiwys` / `ConsequenceTier` | Parse the signed bytes into a human sentence + consequence tier. |
| `WalletSigner` / `ScaffoldSigner` | The on-device signer interface (yields only public outputs); a test stand-in. |
| `SecretKey` / `SeedPhrase` / `WireSafe` | The structural key-material denylist (no `Serialize`, sealed marker). |
| `Channel` / `loopback` | The transport seam (Dev1's paired hybrid-PQ channel); in-memory pair for tests. |

### Reconnect / watermark persistence, in one glance

```rust
use postern_signer_protocol::{seal_watermark, open_watermark};
// storage_key: bytes from the device keystore. The watermark is NOT secret —
// it is a session id + counter — so it is MAC-authenticated (integrity +
// anti-rollback), not encrypted.
let blob = seal_watermark(&guard, storage_key);       // on clean shutdown
// ...restart...
let guard = open_watermark(&blob, storage_key)?;      // wrong key/tamper => Err, no guard
```

---

## Security model

- **Keys never cross the wire — structurally.** The seed and the Falcon‖ML-DSA
  secret live in `secret` types that have **no `Serialize`** and can never be a
  field of a wire message; every message implements the sealed `WireSafe` marker.
  A compile-time census (`_WIRE_CENSUS`) and the runtime golden test
  (`tests/golden_denylist.rs`) both fail the build if any key byte reaches a
  serialized message — as raw bytes, hex, or serde's decimal-array form.
- **WYSIWYS from the actual signed bytes.** There is deliberately **no human-text
  field** on the wire; the phone decodes the payload itself and recomputes a
  domain-separated **SHA3-256** digest from the decoded fields, so a compromised
  desktop cannot narrate a lie, and the human sees exactly the fields that feed
  the digest. An undecodable payload is undisplayable ⇒ **fail closed** (won't
  sign what it can't show).
- **Anti-replay: three independent, fail-closed checks.** Session binding
  (a request for session A cannot replay on B), a strictly-monotonic per-session
  counter, and a single-use nonce. The guard advances **only** on a genuine
  approval, so a declined or rejected request never poisons the sequence.
- **Reconnect model (consistent with `postern-pairing`).** The recommended path
  is a **fresh session per reconnect** (new session id ⇒ old captured frames fail
  the session binding). The `resume` watermark is **defense-in-depth** for
  deployments that keep a stable `session_id` across a brief transport drop: it
  MAC-authenticates the last counter so a restart cannot rewind the monotonic
  gate. Authenticated (not encrypted) because the watermark carries no secret —
  which also keeps the crate dependency-light (`sha3` only, no cipher).
- **Grants are narrow and fail-closed.** A time-boxed, revocable grant may
  auto-approve a *specific single-tap login scope* from a *named peer* — never a
  blanket "approve all", and **never** a value transfer. Revoked or expired both
  collapse to "never given" (mirrors `postern-policy`).

## Honest limits (rails)

- **Software signing in RAM is NOT a hardware wallet.** Even on the phone the PQ
  secret is decrypted into normal RAM to sign (zeroized on drop); on the community
  edition it is pure software. A rooted/malware endpoint (A5) reads the key from
  RAM and can forge the approval UI — nothing here fixes that. This is not a
  Ledger/Trezor.
- **Scaffold, unaudited.** `ScaffoldSigner` is deterministic and not real
  cryptography. Grant enforcement is a **userland, in-process** check, not an OS
  boundary. The watermark protects against passive/offline rollback, not against
  ring-0 that can also forge the MAC.
- **Local-only.** No cloud, no relay, no telemetry — this rides a local, paired,
  hybrid-PQ channel.
- **The coin (BLCH) is not a security**, buys no software, and is not involved in
  licensing — but a "sign" is an irreversible spend; treat it so. The community
  mobile edition is **"Postern for postmarketOS — community edition"**, never
  "Postern OS"; the assurance name is never "BABA YAGA".

## Build & test

```
cargo build
cargo test      # 19 tests (15 original + 4 for the resume watermark):
                # lib (digest layout, WYSIWYS tiers, replay, grants, watermark),
                # tests/flow.rs (end-to-end + adversarial reconnect/replay/decline),
                # tests/golden_denylist.rs (no key material on the wire)
```

## License

Dual-licensed under **MIT OR Apache-2.0**. See `LICENSE-MIT` and `LICENSE-APACHE`.
