//! Postern Messenger — the E2EE messaging core (a Postern Labs product).
//! Pre-release and **UNAUDITED**.
//!
//! Megolm E2EE via `vodozemac` (Apache-2.0, audited by Least Authority 2022) is
//! **real in the default build** — no cargo feature, no homeserver required.
//! Three layers live here over that one crypto stack:
//!
//! - **The default Postern-native path — [`channel`] + [`store`] +
//!   [`transport`]** (always built). A [`channel::SecureChannel`] is a
//!   **persistent** Megolm endpoint: it encrypts/decrypts
//!   [`transport::Frame`]s, **rejects replays**, and **saves its sessions and
//!   replay state encrypted at rest** so everything **survives a restart**
//!   ([`store`]). Frames move over a pluggable transport — in-process
//!   [`transport::LoopbackTransport`] by default, or **Tor** ([`tor`], feature
//!   `tor`). Honest trade: key distribution is **out-of-band** here (you move
//!   the session key to peers yourself), not SDK-automated.
//! - [`matrix`] (cargo feature `matrix`, **off by default**) — the FEDERATED
//!   interop path on **`matrix-rust-sdk`** (Apache-2.0): homeserver login,
//!   sync, and Megolm send/receive with **Olm per-device room-key distribution
//!   handled by the SDK**. Pick this when you want federation + automatic key
//!   distribution; it pulls a large dependency tree, hence off by default. We
//!   build a **fresh** client and **never fork Element / Element Call (AGPL)**
//!   or use **libsignal (AGPL)**.
//! - [`megolm_reference`] — the original hand-rolled Megolm core, **legacy/
//!   reference only** (see its module docs): same vodozemac primitives, but not
//!   wired to a transport or persistence. The default [`channel`] path is what
//!   supersedes it for real use.
//!
//! The [`SecurityTier`] wall and the [`disclosure`] copy (Phase 0) are the
//! data model every layer above must respect: internal E2EE conversations are
//! the *internal* tier; anything bridged/unencrypted/unknown is *bridged* —
//! fail-closed, never silently downgraded.
//!
//! Honest limits (state them in the product, never hide):
//! - **Megolm is classical** (Curve25519) — *not* post-quantum. Harvest-now-
//!   decrypt-later applies to intercepted transport ciphertext. Postern wraps
//!   keys **at rest** with the PQ vault (the default path's [`store`] encrypts
//!   session pickles with a vault-supplied key); transport PQ waits on upstream.
//! - **Metadata**: a homeserver / peer sees timing and the social graph.
//!   Mitigate by carrying frames over **Tor** ([`tor`]). **Tor is OFF by
//!   default (feature `tor`) — a deliberate, documented default, not a promoted
//!   path.** The default build carries frames over the in-process
//!   [`transport::LoopbackTransport`] and opens NO circuit; enabling `tor` pulls
//!   arti and adds only the async socket plumbing over the same
//!   default-built-and-tested [`transport`] frame codec. The live circuit is
//!   VM-gated (an `#[ignore]`d bring-up, like every arti path in this
//!   workspace), so the default cannot honestly claim "carried over Tor" — it
//!   claims exactly what it does: loopback frames, Tor available behind a flag.
//!   (Tor wiring of the *matrix* client is separate Phase-1 remaining work.)
//! - **Persistence**: the DEFAULT [`channel`] path now persists (encrypted at
//!   rest, survives restart) via [`store`]. The `matrix` slice now has a
//!   persistent option too — `login_password_persistent` / `restore` back the
//!   SDK with its sqlite store, passphrase-encrypted at the SDK layer — and
//!   the persisted `SavedSession` (access token) is now **SEALABLE at rest**
//!   via `matrix::SavedSession::seal_to` / `open_sealed` (the workspace's
//!   hybrid X25519+ML-KEM-1024 seal, `postern-courier`). HONEST SCOPE
//!   (machine-checked in `matrix::SEALED_SESSION_LIMITS`): that covers the
//!   SavedSession blob ONLY — sealing is caller-opt-in (plain serde still
//!   emits the token in plaintext), custody of the courier recipient secret
//!   is the caller's (vault integration is the desktop layer's job), the
//!   sqlite store passphrase remains SDK-layer-only (NOT PQ-vault-wrapped),
//!   and `login_password` stays in-memory. Remaining Phase-1 work is
//!   machine-checked in `matrix::PHASE1_REMAINING`.
//! - **Key distribution** on the default path is out-of-band (the honest limit
//!   [`megolm_reference`] states); the `matrix` path automates it over Olm.
//! - **No verification** on the `matrix` path: cross-signing / emoji SAS is
//!   Phase 2, and room classification does not yet account for member
//!   devices. And **live matrix paths are never booted in CI** — live proof
//!   is the `#[ignore]`d `matrix_live` test, run manually; the offline suite
//!   proves shapes and refusals only. This crate is a labelled pre-release
//!   library slice, not a functional messenger product.
//! - Full status ledger: docs/specs/POSTERN-MESSAGING-INTEROP.md §10.

/// The security tier of a conversation — the data model behind the hard wall
/// between internal E2EE chats and externally **bridged** ones (design:
/// `docs/specs/POSTERN-MESSAGING-INTEROP.md`). Two rules are load-bearing:
///
/// 1. **No silent downgrade**: there is deliberately no `Default`, no
///    `From`/conversion between variants, and no "fallback" constructor — a
///    conversation's tier is assigned at classification time (fail-closed:
///    anything not provably internal E2EE is [`SecurityTier::BridgedExternal`])
///    and a bridged conversation must never be presented as internal.
/// 2. **Mandatory disclosure**: when
///    [`requires_persistent_disclaimer`](Self::requires_persistent_disclaimer)
///    is `true`, every UI MUST show the exact copy in [`disclosure`] — pinned
///    on the tab, on the conversation, and at the compose box; never
///    dismissible, never paraphrased.
///
/// STATUS (honest): with the `matrix` feature, rooms ARE now classified
/// fail-closed ([`matrix::classify_room`]) from encryption state + bridge-ghost
/// member scan; device-by-device accounting (cross-signing/verification) is
/// Phase-2 and NOT part of the classification yet. Without the feature this
/// remains the Phase-0 data model only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityTier {
    /// Postern-internal Matrix E2EE — Olm/Megolm end-to-end (this crate's
    /// ratchet). Classical crypto, not post-quantum; homeserver still sees
    /// metadata — the honest limits at the top of this crate apply.
    InternalE2ee,
    /// The conversation crosses a bridge and/or an external service
    /// (e.g. Telegram) that handles **plaintext**. Not operated by Postern;
    /// not protected by Postern. Disclosure is mandatory, not optional.
    BridgedExternal,
}

impl SecurityTier {
    /// `true` iff every UI surface for this conversation MUST permanently
    /// show the [`disclosure`] copy (tab banner, conversation header,
    /// compose-box line).
    pub const fn requires_persistent_disclaimer(self) -> bool {
        matches!(self, SecurityTier::BridgedExternal)
    }

    /// The badge shown in the conversation list, on each message, and at the
    /// compose box. One source of truth so no UI layer softens the wording.
    pub const fn badge(self) -> &'static str {
        match self {
            SecurityTier::InternalE2ee => "E2EE (Postern)",
            SecurityTier::BridgedExternal => "\u{26a0} Bridged — not E2EE",
        }
    }
}

/// The exact, founder-required disclaimer copy for the external Bridges tab —
/// persistent and non-dismissible wherever a [`SecurityTier::BridgedExternal`]
/// conversation appears. UI layers must render these strings verbatim (or a
/// translation preserving all three claims: plaintext readable by bridge +
/// external service; metadata visible to the external service; Postern does
/// not operate or protect it). Copy source: POSTERN-MESSAGING-INTEROP.md §5.
pub mod disclosure {
    /// (a) Pinned banner shown on entering the Bridges tab.
    pub const BRIDGE_TAB_BANNER: &str = "\u{26a0} External bridge — these messages are NOT protected like your Postern chats. Anything you send or receive here leaves Postern's end-to-end encryption: your bridge server and the external service (e.g. Telegram) can read it in plaintext. The external service also sees the metadata — that this conversation exists, when you talk, and who talks to whom. Postern does not operate this bridge and cannot protect these messages.";

    /// (b) Pinned header at the top of every bridged conversation.
    pub const BRIDGED_CONVERSATION_HEADER: &str = "\u{26a0} Bridged conversation — not end-to-end encrypted. The bridge and the external service (e.g. Telegram) can read every message here, and the external service sees when and with whom you talk.";

    /// (c) Permanently visible line next to the compose box.
    pub const BRIDGED_COMPOSE_NOTE: &str = "\u{26a0} Not E2EE — readable by the bridge and the external service.";
}

pub mod channel;
pub mod megolm_reference;
pub mod store;
pub mod transport;

#[cfg(feature = "matrix")]
pub mod matrix;

#[cfg(feature = "tor")]
pub mod tor;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridged_tier_mandates_disclosure_and_internal_does_not() {
        assert!(SecurityTier::BridgedExternal.requires_persistent_disclaimer());
        assert!(!SecurityTier::InternalE2ee.requires_persistent_disclaimer());
    }

    #[test]
    fn tier_badges_are_distinct_and_bridged_badge_warns() {
        assert_ne!(SecurityTier::InternalE2ee.badge(), SecurityTier::BridgedExternal.badge());
        assert_eq!(SecurityTier::InternalE2ee.badge(), "E2EE (Postern)");
        assert!(SecurityTier::BridgedExternal.badge().contains("not E2EE"));
    }

    #[test]
    fn disclosure_copy_carries_all_three_honest_claims() {
        // The founder-required claims must survive any future copy edit:
        // plaintext readable, metadata visible, Postern does not operate it.
        let banner = disclosure::BRIDGE_TAB_BANNER;
        assert!(banner.contains("plaintext"));
        assert!(banner.contains("metadata"));
        assert!(banner.contains("does not operate this bridge"));
        assert!(disclosure::BRIDGED_CONVERSATION_HEADER.contains("not end-to-end encrypted"));
        assert!(disclosure::BRIDGED_COMPOSE_NOTE.contains("Not E2EE"));
    }
}
