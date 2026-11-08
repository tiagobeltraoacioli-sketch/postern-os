# Postern Messenger — Matrix-federation interop + the external Bridges tab

**Status: PHASE 1 IN PROGRESS (first vertical slice landed).** A Postern Labs
design spec (companion crate: `crates/postern-messenger`). Implemented so far:
the Phase-0 security-tier data model (§10) and the first Phase-1 slice — a
feature-gated matrix-rust-sdk client with login/sync and E2EE send/receive
(§10.1 has the honest done/stubbed/remaining ledger). Everything else is
design. Judged against `PRINCIPLES.md`, the permissive-license rule
(`docs/POSTERN-APPS-ROADMAP.md`), and the honesty rule: every limit is
stated in the product, never hidden. The messenger is pre-release and
**UNAUDITED**.

**The feature, in one line ("capillarity"):** Postern Messenger reaches the
open messaging world by **speaking Matrix and joining the federated network**
— which preserves its own E2EE ratchet end-to-end — and reaches closed
networks (Telegram, WhatsApp, Signal) **transitively, through existing
third-party bridges the user hosts**, shown in a visually and logically
**separate "Bridges" tab** that never pretends to be secure.

---

## 1. Ground truth — what exists today (honest baseline)

- `crates/postern-messenger` now has **two layers, one live crypto stack**:
  - **`matrix` module (cargo feature `matrix`, OFF by default)** — the first
    Phase-1 slice on `matrix-rust-sdk` 0.18 (Apache-2.0; its E2EE is
    `vodozemac`): homeserver password **login**, **sync**, fail-closed room
    classification onto `SecurityTier`, tier-gated **E2EE (Megolm) send**,
    and decrypted **receive** — with **Olm per-device room-key distribution
    handled by the SDK**, closing this crate's long-stated gap. See §10.1
    for exactly what is done vs remaining (no persistence, no Tor, no
    verification yet).
  - **`megolm_reference` module** — the original hand-rolled Megolm core
    (direct `vodozemac`), now explicitly **legacy/reference only**: small,
    tested (roundtrip, index advance, replay rejection), wired to no
    transport, and never to be composed with the `matrix` module. Decision
    record in §10.1.
- There is still **no UI, no homeserver of ours, no calls, no session
  persistence** — the slice is a library layer, not a product.
- `crates/postern-courier` is a **different product** (serverless PQ file
  drop). It is not part of this design and must not be conflated with it.

Everything not in §10's "done" column is **design**, phased honestly in §10.

## 2. Why the interop target is Matrix federation — not Telegram

The core is **already Megolm** — Matrix's own group ratchet. That makes the
Matrix federated network the *natural* interop surface, and the only one where
Postern's E2EE survives the trip:

| Path | E2EE preserved? | Who Postern can reach | Verdict |
|---|---|---|---|
| **Matrix federation** (this design) | **yes** — same Olm/Megolm ratchet end-to-end with any Matrix E2EE client | the whole federated Matrix ecosystem (Element users, self-hosters, orgs) | **build** |
| Telegram Bot API / MTProto client | no — Telegram's crypto, Telegram's servers, no E2EE for groups/bots at all | Telegram only | reject as a *direct* target |
| Postern-operated bridge relaying plaintext | no — Postern would see plaintext | anyone, at the cost of the entire ethos | **rejected outright** (§6) |
| **Existing third-party bridges (mautrix), user-hosted** | no (inherent to bridging) — but **disclosed, opt-in, and not operated by Postern** | Telegram, WhatsApp, Signal, Discord, … *transitively* | **support, behind the hard wall** (§4–§6) |

So one Matrix client buys two kinds of capillarity:

1. **Native reach** into all of federated Matrix, with E2EE intact.
2. **Transitive reach** into closed networks via the mature, existing
   **mautrix** bridge family (Apache-2.0/AGPL — run as *separate services by
   the user*, never linked or forked; see license note §11). Postern builds
   **no bridge and operates no bridge**.

### 2.1 Architecture (client-side; federation is the homeserver's job)

An honest clarification: "Matrix federation" is **server-to-server**. A client
does not implement federation — it joins the federated network *through its
homeserver*. Postern Messenger is a **fresh Apache/MIT client** on
**`matrix-rust-sdk`** (Apache-2.0; login/sync/rooms/timeline) with
**`vodozemac`** as the crypto (already this crate's dependency). Never a fork
of Element / Element X / Element Call (AGPL); never libsignal (AGPL).

```
Postern Messenger (fresh client, matrix-rust-sdk + vodozemac)
        │  Matrix client-server API (over Tor via postern-tor)
        ▼
User's homeserver (self-hosted continuwuity, Apache-2.0 — or any homeserver)
        │  Matrix federation (server-to-server)          │  Matrix appservice API
        ▼                                                ▼
The federated Matrix network                 USER-HOSTED mautrix bridge(s)
(E2EE preserved: internal tier)                       │  external protocol
                                                      ▼
                                             Telegram / WhatsApp / … servers
                                             (plaintext to them: bridged tier)
```

Postern Labs operates **neither** the homeserver **nor** the bridge
(no-server ethos). Recommended homeserver: self-hosted **continuwuity**
(Apache-2.0; verify maturity at adoption), reached over Tor, no phone-number
identity.

## 3. How E2EE is preserved on the internal (Matrix) tier

- **Same ratchet end-to-end.** Room messages are Megolm-encrypted by this
  crate's crypto (via the SDK); any standards-compliant Matrix E2EE client on
  any federated homeserver decrypts with its own Olm/Megolm — the homeservers
  in between see only ciphertext. No re-encryption hop, no Postern gateway.
- **Key distribution** is the standard Matrix mechanism: the Megolm session
  key is shared **Olm-encrypted per recipient device** (`m.room_key` over
  Olm), handled at the `matrix-rust-sdk` layer. This is not a Postern
  invention — and as of the Phase-1 slice it is **implemented** (the SDK does
  it on the crate's tier-gated send path; see §10.1 for verification status).
- **Verification**: cross-signing + emoji SAS (SDK-provided) so "internal
  E2EE" can also mean "verified devices"; unverified-device warnings surface
  in the same badge system as §4.
- **Replay**: the crate's `(session_id, message_index)` dedup carries over;
  the client persists it (required for cross-restart protection).
- **Honest crypto limits** (already stated in the crate, restated in-product):
  Megolm is **classical** (Curve25519), not post-quantum —
  harvest-now-decrypt-later applies to intercepted transport ciphertext.
  Postern PQ-wraps keys **at rest** with the vault; transport PQ waits on
  upstream Matrix MSCs. The homeserver sees **metadata** (membership,
  timing) — mitigated, not eliminated, by self-hosting + Tor.

## 4. The Bridges tab — a hard wall, not a blur

Two tiers, two spaces. Internal E2EE chats and bridged external conversations
are **visually and logically separate**: a distinct top-level **"Bridges"
tab**, its own conversation list, its own accent/warning styling. No mixed
lists, no unified inbox, no "smart" merging.

### 4.1 Security badges — per conversation AND per message

- **Conversation list**: every conversation row carries a tier badge —
  internal rows show **“E2EE (Postern)”**; bridged rows show
  **“⚠ Bridged — not E2EE”**. Visible in the list itself, not behind a tap.
- **Inside a conversation**: every message renders with its tier badge, and
  the **compose box** shows the tier of what you are about to send —
  internal: “E2EE (Postern)”; bridged: the persistent disclaimer of §5.
- The badge strings and the disclaimer copy live as constants in
  `postern-messenger` (§10 Phase 0) so every UI layer shows the **same
  honest words** — no per-platform paraphrasing drift.

### 4.2 NO silent downgrade — ever

If an internal contact is unreachable (offline, homeserver down, keys
missing), the app **never** auto-falls-back to a bridge, never suggests
"reach them on Telegram instead" inside the internal flow, and never
converts a conversation's tier. Reaching someone over a bridge is only ever
the result of the user **explicitly opening the Bridges tab** and choosing a
bridged conversation. Failure states in the internal tab say "unreachable",
full stop.

### 4.3 Security-tier data model (encodes the wall in the type system)

```rust
/// The two tiers. There is deliberately NO conversion between them and NO
/// default: a conversation's tier is assigned at classification time and a
/// bridged conversation can never be presented as internal.
pub enum SecurityTier {
    /// Postern-internal Matrix E2EE (Olm/Megolm end-to-end).
    InternalE2ee,
    /// Crosses a bridge and/or an external service that reads plaintext.
    /// `requires_persistent_disclaimer()` is true — UI MUST show §5's copy.
    BridgedExternal,
}
```

**Classification is fail-closed.** A conversation is `InternalE2ee` **only
if** the room is encrypted **and** no member matches a bridge namespace
(mautrix ghost users / bridge bot, declared in the appservice registration)
**and** the client can account for every member as a Matrix E2EE device.
Anything else — a bridge ghost present, encryption off, an unclassifiable
member — is `BridgedExternal` (or simply "warned"). Unknown never defaults
to safe-looking.

## 5. The disclaimer — exact copy (founder requirement: persistent, always visible)

The Bridges tab carries a **persistent, non-dismissible** disclaimer. It is
shown (a) as a pinned banner on entering the tab, (b) at the top of every
bridged conversation, and (c) as a permanent line at the compose box. The
exact copy (single source of truth in `postern_messenger::disclosure`):

**(a) Bridges-tab banner — on entering the tab, pinned, not dismissible:**

> ⚠ **External bridge — these messages are NOT protected like your Postern
> chats.** Anything you send or receive here leaves Postern's end-to-end
> encryption: your bridge server and the external service (e.g. Telegram)
> can read it in plaintext. The external service also sees the metadata —
> that this conversation exists, when you talk, and who talks to whom.
> Postern does not operate this bridge and cannot protect these messages.

**(b) Bridged-conversation header — pinned at the top of every bridged chat:**

> ⚠ Bridged conversation — not end-to-end encrypted. The bridge and the
> external service (e.g. Telegram) can read every message here, and the
> external service sees when and with whom you talk.

**(c) Compose-box line — permanently visible next to the input field:**

> ⚠ Not E2EE — readable by the bridge and the external service.

Copy rules: never soften ("mostly private", "encrypted in transit" as
reassurance), never hide behind an info icon, never show once-and-dismiss.
Translations must preserve the three claims: **plaintext readable by bridge +
external service; metadata visible to the external service; Postern does not
operate or protect it.**

## 6. Postern does NOT operate the bridge

- The design uses a **user-hosted mautrix bridge** (e.g. mautrix-telegram /
  mautrix-whatsapp / mautrix-signal running as the user's own appservice next
  to their self-hosted homeserver) or an **existing third-party bridge** the
  user already trusts. Postern ships **documentation and detection**, not a
  bridge service.
- Consequence, stated plainly: **Postern never sees bridged plaintext**,
  consistent with the no-server ethos. The party that does see plaintext is
  the party the *user* chose and hosts (their bridge) plus the external
  service itself — exactly what §5's copy says.
- **Rejected design**: any variant where Postern Labs runs a relay, a hosted
  bridge, or a "connect your Telegram" cloud service. That would put user
  plaintext on Postern infrastructure — the one thing the company model
  forbids. This rejection is load-bearing; do not revisit it for growth
  reasons.
- Honest limit: a bridge is a **single point of compromise** for its
  conversations — whoever controls the bridge host reads everything crossing
  it (§9).

## 7. Video — the honest note

- **Interop path: Matrix-native video** — MatrixRTC (Element Call's
  underlying spec family: MSC3401 and related) over **WebRTC** (`libwebrtc`,
  BSD-3). A fresh implementation or SDK support only — **Element Call itself
  is AGPL: no fork, no embed**. 1:1 WebRTC calls first; group calls
  (SFU-based, e.g. LiveKit — verify license at adoption) are a later phase.
- **Telegram video is proprietary MTProto and not interoperable.** No bridge
  carries a live Telegram video call into Matrix. There will be **no video on
  the Bridges tab**; the tab says so rather than pretending. Cross-network
  video interop is out of scope, honestly.

## 8. Naming

The app keeps the house-marked name **"Postern Messenger"** (founder
decision), and the internal crate name `postern-messenger` (descriptive) is
unchanged. Rationale: prefixing with the "Postern" house brand and using
"messenger" descriptively is materially **more defensible** than a bare
standalone "Messenger" — which is primarily Meta/Facebook's mark today, and
historically Microsoft's. The public product is never branded bare
"Messenger".

This is NOT legal advice — residual trademark risk remains in the same
product category; run a trademark search / consult IP counsel before
finalizing (applies to all Postern product names, which POSTERN-LABS.md marks
provisional).

## 9. Honest limits (state them in the product, never hide)

1. **Bridged tier is not private.** The bridge host and the external service
   read plaintext; the external service sees existence/timing/social-graph
   metadata. That is what §5 says to the user, permanently.
2. **The bridge is a single point of compromise** for every conversation
   crossing it — user-hosting moves the trust to the user, it does not
   remove it.
3. **Matrix metadata**: even on the internal tier, homeservers see room
   membership and timing; federation shares room state with every
   participating server. Mitigation (self-hosted continuwuity + Tor + no
   phone numbers) reduces, does not eliminate, this.
4. **Megolm is classical, not PQ** — harvest-now-decrypt-later applies to
   transport; at-rest keys are PQ-wrapped in the vault; transport PQ waits
   on upstream Matrix.
5. **Federation widens exposure**: joining federated rooms means trusting
   the other rooms' homeservers with room metadata, and accepting the
   ecosystem's abuse surface (invite spam, malicious servers replaying —
   hence this crate's replay rejection).
6. **Nothing past Phase 0 exists.** Full Matrix federation support —
   client, key distribution, verification, sync — is **substantial work**
   (matrix-rust-sdk carries much of it, but integration, persistence, UI,
   and audit are real projects, not a sprint).

## 10. Phased plan (buildable-now vs roadmap, honestly)

| Phase | Scope | Builds on | Effort honesty |
|---|---|---|---|
| **0 — done** | `SecurityTier` enum + mandatory-disclosure flag + the §5 copy as constants in `postern-messenger`; this design doc; roadmap registration | current crate, no new deps | small, shipped green |
| **1 — the client core (IN PROGRESS — first slice landed, see §10.1)** | matrix-rust-sdk client: login, sync, rooms, **Olm per-device session-key distribution** (closes the crate's stated gap), persistent `(session_id, message_index)` replay store, self-hosted-homeserver + Tor wiring | Phase 0 + matrix-rust-sdk | **substantial** — this is "build the messenger" |
| **2 — federation + trust UX** | federated rooms via the user's homeserver; cross-signing/SAS verification; tier badges wired per conversation + per message + compose box | Phase 1 | moderate on top of 1 |
| **3 — the Bridges tab** | separate tab; fail-closed bridge-room classification (appservice namespaces/ghost users + manual override to *warned only*, never to internal); persistent disclaimers (§5); user-hosted mautrix setup docs; **no silent downgrade** enforced in the conversation-open path | Phase 2 + user-hosted bridge | moderate; zero bridge code written or operated by Postern |
| **4 — video** | MatrixRTC 1:1 over libwebrtc (fresh, never Element Call); group/SFU later; explicitly **no bridged video** | Phase 2 | large; later |

Ordering rule: the wall (Phase 0) exists **before** any bridge UX, so no
intermediate build can ever show a bridged conversation without its tier.

### 10.1 Phase-1 status ledger (2026-07 — honest: done / stubbed / remaining)

The first Phase-1 vertical slice is in `crates/postern-messenger` behind the
**optional cargo feature `matrix`** (OFF by default — matrix-rust-sdk is a
large tree and the default workspace gate stays lean):

```
cargo build -p postern-messenger --features matrix
cargo test  -p postern-messenger --features matrix              # offline units
cargo test  -p postern-messenger --features matrix -- --ignored # live round-trip
```

**DONE (implemented and verified):**

- **matrix-rust-sdk 0.18 integration** (`postern_messenger::matrix`,
  Apache-2.0; E2EE via vodozemac 0.10 inside the SDK).
- **Login** (password), **sync**, tier-gated **E2EE send**, decrypted
  **receive** with per-message `was_encrypted` + `SecurityTier` stamps.
- **Olm per-device room-key distribution** — the crate's long-stated gap —
  now handled by the SDK on the send path (`m.room_key` over Olm).
- **Fail-closed classification** (`matrix::classify_room`): internal tier
  ONLY for known-encrypted rooms with no member in a bridge namespace
  (default mautrix prefixes); unencrypted/unknown/ghost ⇒ bridged. Pure and
  unit-tested.
- **No-silent-downgrade enforced in code**: `send_text` refuses any room not
  classified `InternalE2ee` (no "send anyway" flag), and double-checks the
  SDK's post-send encryption info.
- **Verified live** (2026-07-10, developer machine, not CI): the `#[ignore]`d
  integration test `tests/matrix_live.rs` ran against a throwaway local
  Synapse in docker — two fresh logins, encrypted private room, invite/join,
  both sides classify `InternalE2ee`, Alice's tier-gated send, Bob receives
  the exact plaintext with `was_encrypted == true`. Offline unit tests +
  the default workspace suite stay green with the feature off.

**ONE CRYPTO STACK (decision record):** matrix-rust-sdk/vodozemac **owns
E2EE** from Phase 1 on. The original hand-rolled Megolm core was moved to
`postern_messenger::megolm_reference` — explicitly **legacy/reference only**
(small, tested, transport-less; useful as an auditable illustration of the
bare ratchet). It must never be composed with the `matrix` module and no new
callers may adopt it. There are not two live crypto stacks.

**REMAINING in Phase 1 (not started or not done — do not overclaim):**

- **Persistence**: the slice runs the SDK's in-memory store. Olm/Megolm
  sessions, sync tokens, and decryption/replay bookkeeping are lost on
  restart (every login is a new device). Needed: the SDK's sqlite store (or
  a custom store) wrapped by the Postern PQ vault — including the durable
  `(session_id, message_index)` replay story.
- **Tor wiring**: the client speaks plain TLS today; routing its HTTP through
  `postern-tor` is designed, not implemented.
- **Session restore / logout / device management**; error-taxonomy hardening.
- Verification (cross-signing/SAS) remains **Phase 2**; classification does
  not yet account for member devices — stated in the code docs.
- The messenger remains **pre-release and UNAUDITED**.

**Supply-chain notes (cargo-deny, all resolved — no open blocker):**

- Adding matrix-sdk to the workspace initially FAILED to resolve: its sqlite
  backend needs `libsqlite3-sys 0.35` while arti 0.28 (via `postern-tor`)
  locked `0.30.1`, and cargo allows one `links = "sqlite3"` package per
  lockfile (optional deps are still locked). Fixed by upgrading
  **arti-client 0.28 → 0.44** in `postern-tor` (thin-wrapper API change:
  arti now hands out `Arc<TorClient>`; workspace stays green) — which also
  **resolved RUSTSEC-2025-0009** (ring 0.16 left the graph).
- **BSL-1.0** (Boost Software License — OSI-approved permissive, NOT the
  "Business Source" BUSL) added to `deny.toml` allow-list for `xxhash-rust`
  (via matrix-sdk). Feature-on graph: licenses/bans/sources **ok**,
  advisories **ok** (the matrix tree adds zero advisories; the workspace's
  three known-open ones predate this work and come via `bloch`/arti — see
  deny.toml).
- Direct `vodozemac` dep bumped 0.8 → 0.10 to match the SDK's (one copy in
  the lockfile); the reference module now uses Megolm **v1** — the actual
  Matrix wire format (vodozemac 0.10 gates the non-interop v2 behind an
  experimental feature).

## 11. License notes (permissive rule)

`vodozemac`, `matrix-rust-sdk`, continuwuity — Apache-2.0: use. Element /
Element X / Element Call, Synapse/Dendrite, libsignal — AGPL: never fork,
never embed (users may self-host servers). **mautrix bridges** (variously
Apache-2.0 and AGPL-3.0 by bridge): acceptable **only** as separate,
user-operated network services spoken to over the Matrix appservice/CS API —
no linking, no vendoring, no forking; re-verify each bridge's current license
at adoption. `libwebrtc` BSD-3: use. Pin/vendor matrix-rust-sdk versions
(currently 0.18, pinned through the committed Cargo.lock). One transitive
addition vetted at adoption time: `xxhash-rust` under **BSL-1.0** — the Boost
Software License, OSI-approved MIT-class permissive (not BUSL) — allow-listed
in `deny.toml`. Synapse (AGPL) is only ever *run* as a throwaway test service
for the live integration test — never linked, never forked, consistent with
the self-hosted-server rule.
