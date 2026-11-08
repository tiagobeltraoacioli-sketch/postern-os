//! Phase-1 Matrix client slice (cargo feature `matrix`) — pre-release,
//! **UNAUDITED**.
//!
//! A thin, honest wrapper over **`matrix-rust-sdk`** (Apache-2.0) giving
//! Postern Messenger its first real Matrix legs:
//!
//! - password **login** against any homeserver ([`MatrixMessenger::login_password`]),
//! - **sync**, one round-trip at a time ([`MatrixMessenger::sync_once`]) or as
//!   a backgrounded retry loop ([`MatrixMessenger::sync_loop`], see its
//!   HONEST CAVEAT — not yet run against a live homeserver by this crate's
//!   offline suite),
//! - **E2EE send** into encrypted rooms ([`MatrixMessenger::send_text`]) —
//!   the SDK Megolm-encrypts the event and does the **Olm per-device
//!   room-key distribution** (`m.room_key` over Olm) that this crate
//!   historically lacked,
//! - **receive** decrypted messages ([`MatrixMessenger::on_text_message`]),
//!   each stamped with its fail-closed [`SecurityTier`],
//! - fail-closed **room classification** ([`classify_room`] /
//!   [`MatrixMessenger::room_tier`]) wiring rooms to the Phase-0
//!   [`SecurityTier`] wall.
//!
//! One crypto stack: the SDK's E2EE is `vodozemac` (Apache-2.0, audited 2022)
//! — the same primitives as [`crate::megolm_reference`], which is legacy/
//! reference only and must never be composed with this module.
//!
//! # What this slice does NOT do yet (Phase-1 remaining — do not overclaim)
//!
//! - **Persistence via SDK sqlite store, passphrase-encrypted — NOT yet
//!   wrapped by the Postern PQ vault (remaining)**: [`MatrixMessenger::login_password`]
//!   still uses the SDK's default in-memory store (fresh device keys every
//!   run). [`MatrixMessenger::login_password_persistent`] instead builds the
//!   client with `.sqlite_store(path, Some(passphrase))` (matrix-sdk-sqlite,
//!   Apache-2.0 -> rusqlite, MIT — both permissive) so Olm/Megolm sessions,
//!   sync tokens, and decryption/replay bookkeeping survive restart. The
//!   passphrase encrypts that on-disk store at the SDK layer; it is NOT yet
//!   wrapped by the Postern PQ vault — that composition is the next Phase-1
//!   step.
//! - **No Tor wiring**: connections go over plain TLS; routing the client's
//!   HTTP through `postern-tor` is designed but not implemented.
//! - **No verification**: cross-signing / emoji SAS is Phase 2. Classification
//!   accounts for room encryption + bridge-ghost members, NOT yet for
//!   device-by-device accounting.
//! - **Session save/restore exists ([`SavedSession`], [`MatrixMessenger::session`],
//!   [`MatrixMessenger::restore`]) and the session blob is now SEALABLE at
//!   rest** via [`SavedSession::seal_to`] / [`SavedSession::open_sealed`]
//!   (the workspace's hybrid X25519+ML-KEM-1024 seal, `postern_courier`).
//!   Sealing is caller-opt-in — plain `serde_json` on a [`SavedSession`]
//!   still emits the bearer token in plaintext — and custody of the courier
//!   recipient secret is the caller's (vault integration is the desktop
//!   layer's job). See [`SEALED_SESSION_LIMITS`] for the full honest scope.
//!   No key-backup/recovery (SSSS/4S), no rooms UI, no calls.
//! - **Classical crypto**: the SDK's Megolm/Olm runs over Curve25519 — NOT
//!   post-quantum. Harvest-now-decrypt-later applies to intercepted
//!   ciphertext; the crate-level honest limits apply unchanged, and the
//!   whole crate remains pre-release and **UNAUDITED**.
//! - **Live paths never booted in CI**: everything network-touching is
//!   proven live only by the `#[ignore]`d `tests/matrix_live.rs`, run
//!   manually against a throwaway homeserver. The offline unit suite proves
//!   shapes and refusals, not live behavior.
//! - **Homeserver metadata is NOT hidden on this path**: see
//!   [`HOMESERVER_METADATA_LIMITS`] for exactly what the homeserver sees on
//!   login/sync/room-list, and why that is unavoidable at the Matrix layer
//!   until the (not-yet-wired) Tor mitigation lands.
//!
//! This remaining list is machine-checked, same pattern as
//! [`HOMESERVER_METADATA_LIMITS`]: [`PHASE1_REMAINING`] restates it as one
//! string and the `phase1_remaining_names_every_open_caveat` unit test pins
//! the claims, so a future copy edit cannot silently drop a caveat.
//!
//! # Enable + test
//!
//! ```text
//! cargo build -p postern-messenger --features matrix
//! cargo test  -p postern-messenger --features matrix          # offline units
//! cargo test  -p postern-messenger --features matrix -- --ignored   # live (see tests/matrix_live.rs)
//! ```

use matrix_sdk::{
    Client, ClientBuildError, Room, RoomMemberships, SessionMeta, SessionTokens,
    authentication::matrix::MatrixSession,
    config::SyncSettings,
    deserialized_responses::EncryptionInfo,
    ruma::{
        DeviceId, OwnedDeviceId, OwnedEventId, OwnedRoomId, OwnedUserId, RoomId, UserId,
        api::client::room::{Visibility, create_room::v3::Request as CreateRoomRequest},
        events::{
            EmptyStateKey, InitialStateEvent,
            room::encryption::RoomEncryptionEventContent,
            room::message::{MessageType, OriginalSyncRoomMessageEvent, RoomMessageEventContent},
        },
    },
    store::RoomLoadSettings,
};
use std::sync::Arc;
use std::time::Duration;

use crate::SecurityTier;

/// Errors from the Matrix client slice.
#[derive(Debug, thiserror::Error)]
pub enum MatrixError {
    /// Boxed on purpose: `ClientBuildError` is this enum's largest payload
    /// (>=160 bytes unboxed) and, inline, it made every `Result<_, MatrixError>`
    /// carry that weight — `clippy::result_large_err` fired on
    /// [`SavedSession::seal_to`] / [`SavedSession::open_sealed`]. The manual
    /// `From<ClientBuildError>` impl below keeps `?` working exactly as
    /// `#[from]` did; the `matrix_error_stays_small_enough_for_result` test
    /// pins the size so the variant cannot silently regrow.
    #[error("building matrix client failed: {0}")]
    Build(#[source] Box<ClientBuildError>),
    #[error("matrix error: {0}")]
    Sdk(#[from] matrix_sdk::Error),
    #[error("unknown room {0} (not in this client's sync state yet — sync first)")]
    UnknownRoom(OwnedRoomId),
    /// The no-silent-downgrade rule, enforced at the send path: this Phase-1
    /// client sends ONLY into rooms classified [`SecurityTier::InternalE2ee`].
    /// Sending into bridged/unencrypted rooms arrives with the Bridges tab
    /// (Phase 3), explicitly and disclosed — never as a fallback.
    #[error("refusing to send: room {room} is classified {tier:?}, not InternalE2ee — no silent downgrade")]
    NotInternalE2ee { room: OwnedRoomId, tier: SecurityTier },
    /// Should be unreachable (the tier gate precedes every send): the SDK
    /// reported NO encryption info for an event sent into a room we
    /// classified internal. The event {event} already left as plaintext —
    /// surfaced loudly so the caller can warn the user, never hidden.
    #[error("event {event} in room {room} was sent WITHOUT encryption despite an InternalE2ee classification")]
    SentUnencrypted { room: OwnedRoomId, event: OwnedEventId },
    /// Sealing/opening a [`SavedSession`] at rest via the postern-courier
    /// hybrid seal failed. Deliberately coarse on the open path (courier's
    /// own policy): "wrong key" vs "tampered blob" is not distinguished —
    /// both fail closed as [`postern_courier::CourierError::Open`].
    #[error("sealed SavedSession at-rest crypto failed: {0}")]
    SessionSeal(#[from] postern_courier::CourierError),
    /// A [`SavedSession`] failed to (de)serialize while sealing/opening the
    /// at-rest blob. On the open path this fires only AFTER the courier seal
    /// authenticated the blob (AEAD), i.e. the blob decrypted fine but did
    /// not contain a `SavedSession` JSON document.
    #[error("sealed SavedSession (de)serialization failed: {0}")]
    SessionCodec(#[from] serde_json::Error),
}

/// Hand-written (instead of `#[from]`) only because the variant boxes its
/// payload — see the note on [`MatrixError::Build`]. `?` on a
/// `Result<_, ClientBuildError>` behaves exactly as before.
impl From<ClientBuildError> for MatrixError {
    fn from(err: ClientBuildError) -> Self {
        Self::Build(Box::new(err))
    }
}

/// What this module knows about a room's encryption when classifying it.
/// Deliberately three-valued: "don't know" must never classify as internal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomEncryption {
    /// The room has a usable `m.room.encryption` state event.
    Encrypted,
    /// The room is known to be unencrypted.
    NotEncrypted,
    /// Sync hasn't provided enough state to decide. Fail-closed: NOT internal.
    Unknown,
}

/// What the homeserver sees on the login/sync/room-list path, stated
/// explicitly and machine-checked (see the `homeserver_metadata_limits_*`
/// tests below) so this honest limit cannot silently drift out of sync with
/// the module docs above.
///
/// On this Phase-1 path — login, sync, room-list — the homeserver
/// UNAVOIDABLY sees, at the Matrix protocol layer, regardless of E2EE:
///
/// 1. **that you exist and are online** — your account, and sync's
///    long-poll/timeout traffic, tells it your presence and connectivity;
/// 2. **your room memberships and the social graph** — which rooms you are
///    in, and therefore who else is in each room (who talks to whom);
/// 3. **message timing** — when events are sent and received (`origin_server_ts`,
///    sync intervals), even though E2EE hides the message body;
/// 4. **your device list** — every Matrix device you register (for Olm
///    key distribution), including its display name.
///
/// This is UNAVOIDABLE at the Matrix layer: the homeserver is the routing
/// hub for login, sync, and room membership, so it necessarily observes
/// existence/online-ness, the social graph, timing, and devices even when
/// message *content* is end-to-end encrypted.
///
/// HONEST CAVEAT — the mitigation is OFF here: carrying this traffic over
/// Tor (to at least separate network identity from the account) is designed
/// but **NOT wired for the Matrix client yet** (Phase-1 remaining work, see
/// "No Tor wiring" above). This slice therefore must NOT claim metadata
/// protection on the login/sync/room-list path — only message *content*
/// gets Megolm/Olm E2EE, and only for rooms classified
/// [`SecurityTier::InternalE2ee`].
pub const HOMESERVER_METADATA_LIMITS: &str = "Homeserver metadata limits (login/sync/room-list): \
the homeserver you connect to unavoidably sees (1) that you exist and are online, \
(2) your room memberships and the social graph of who is in which room, \
(3) message timing — when you send and receive, even though content is E2EE, and \
(4) your device list. This is unavoidable at the Matrix protocol layer. \
The Tor mitigation for this (routing the client's traffic over Tor to decouple network \
identity from the account) is designed but NOT wired for the matrix client yet \
(Phase-1 remaining) — this slice does not claim metadata protection.";

/// The Phase-1 remaining-work ledger as one machine-checked string — the
/// same pattern as [`HOMESERVER_METADATA_LIMITS`] (see the
/// `phase1_remaining_names_every_open_caveat` test below) — so the module
/// docs' "What this slice does NOT do yet" list above cannot silently drift
/// into overclaiming as slices land. Every claim here stays until the code
/// actually does the thing; when an item genuinely lands, it moves out of
/// BOTH the module docs and this string in the same commit, and the test is
/// updated to match. UI layers may surface this string verbatim.
pub const PHASE1_REMAINING: &str = "Phase-1 remaining work (do not overclaim): \
(1) Tor is NOT wired for the matrix client — login/sync/send go over plain TLS, so this \
path claims no metadata protection; \
(2) no verification — cross-signing / emoji SAS is Phase 2, and room classification does \
not yet account for member devices; \
(3) the E2EE is classical Megolm/Olm over Curve25519 — NOT post-quantum; \
harvest-now-decrypt-later applies to intercepted ciphertext; \
(4) the SavedSession access token is now SEALABLE at rest — SavedSession::seal_to / \
open_sealed wrap the persisted blob with the workspace's hybrid X25519+ML-KEM-1024 seal \
(postern-courier) — but sealing is caller-opt-in (plain serde on a SavedSession still \
emits the token in plaintext), custody of the courier recipient secret is the caller's \
(whoever holds it can open the blob and act as this Matrix device; vault integration is \
the desktop layer's job), and the sqlite store passphrase remains SDK-layer-only — the \
sqlite files are NOT wrapped by the Postern PQ vault; \
(5) the live login/sync/send paths are never booted in CI — live proof is the #[ignore]d \
matrix_live test, run manually; \
and the whole crate remains a pre-release, UNAUDITED library slice — not a functional \
messenger product.";

/// The honest scope of [`SavedSession::seal_to`] / [`SavedSession::open_sealed`]
/// as one machine-checked string (see the
/// `sealed_session_limits_names_every_honest_caveat` test below — same
/// pattern as [`HOMESERVER_METADATA_LIMITS`] / [`PHASE1_REMAINING`]), so a
/// future copy edit cannot silently soften a caveat. UI layers surfacing the
/// sealed-session capability MUST surface this string (or a translation
/// preserving every claim) alongside it.
pub const SEALED_SESSION_LIMITS: &str = "Sealed-at-rest applies to the persisted \
SavedSession blob ONLY: the Megolm/Olm transport crypto remains classical Curve25519 \
(NOT post-quantum; harvest-now-decrypt-later applies), the SDK's sqlite store keeps \
only its own passphrase encryption (not PQ-wrapped), whoever holds the courier \
recipient secret can open the blob and act as this Matrix device, the in-process \
SavedSession is NOT an in-memory secrecy boundary (the access token lives in a plain \
String — only the seal/open intermediate JSON buffer is zeroized; serde may leave \
transient heap copies), and the whole crate remains pre-release and UNAUDITED.";

/// Matrix-ID prefixes of well-known bridge ghost users and bridge bots (the
/// mautrix family's defaults). A room containing any matching member is
/// classified [`SecurityTier::BridgedExternal`] even if encrypted — the bridge
/// re-plaintexts on the far side.
///
/// HONEST LIMIT: these are the *default* namespaces; a bridge admin can pick
/// any namespace. The reliable source is the user's own appservice
/// registration (Phase 3 reads it); until then this list errs toward warning
/// and the encryption check still gates the internal tier.
pub const DEFAULT_BRIDGE_USER_PREFIXES: &[&str] = &[
    "@telegram_",
    "@telegrambot:",
    "@whatsapp_",
    "@whatsappbot:",
    "@signal_",
    "@signalbot:",
    "@discord_",
    "@discordbot:",
    "@slack_",
    "@slackbot:",
    "@instagram_",
    "@instagrambot:",
    "@facebook_",
    "@facebookbot:",
    "@messenger_",
    "@gmessages_",
    "@imessage_",
];

/// Fail-closed room classification (design doc §4.3), pure and offline-
/// testable. A room is [`SecurityTier::InternalE2ee`] **only if** it is
/// known-encrypted AND no member's Matrix ID matches a bridge namespace.
/// Everything else — unencrypted, encryption state unknown, a ghost present —
/// is [`SecurityTier::BridgedExternal`]. Unknown never defaults to
/// safe-looking.
///
/// (Phase-2 will additionally require accounting for every member as a
/// verified Matrix E2EE device; that check does not exist yet.)
pub fn classify_room<'a>(
    encryption: RoomEncryption,
    member_ids: impl IntoIterator<Item = &'a str>,
    bridge_user_prefixes: &[&str],
) -> SecurityTier {
    if encryption != RoomEncryption::Encrypted {
        return SecurityTier::BridgedExternal;
    }
    for member in member_ids {
        if bridge_user_prefixes.iter().any(|p| member.starts_with(p)) {
            return SecurityTier::BridgedExternal;
        }
    }
    SecurityTier::InternalE2ee
}

/// Build the (unsent) request for a **private, encrypted, direct** Matrix
/// room with `invitee` invited — pure, offline, no I/O. This is the ONLY
/// room-creation shape this crate builds: `visibility` is always
/// [`Visibility::Private`], `is_direct` is always `true`, and
/// `initial_state` always carries exactly one `m.room.encryption` event
/// (via [`RoomEncryptionEventContent::with_recommended_defaults`]).
///
/// Deliberately no plaintext/unencrypted variant exists on this crate's
/// public surface — mirrors the no-silent-downgrade rule at the send gate
/// ([`MatrixMessenger::send_text`]): there is no "create anyway" flag here
/// either.
pub fn encrypted_dm_request(invitee: &UserId) -> CreateRoomRequest {
    let mut request = CreateRoomRequest::new();
    request.visibility = Visibility::Private;
    request.invite = vec![invitee.to_owned()];
    request.is_direct = true;
    request.initial_state = vec![
        InitialStateEvent::new(EmptyStateKey, RoomEncryptionEventContent::with_recommended_defaults())
            .to_raw_any(),
    ];
    request
}

/// A text message received (and, for encrypted rooms, already Megolm-decrypted
/// by the SDK) from sync.
#[derive(Debug, Clone)]
pub struct ReceivedText {
    pub room_id: OwnedRoomId,
    pub sender: OwnedUserId,
    pub event_id: OwnedEventId,
    pub body: String,
    /// `true` iff the event arrived E2EE and was decrypted (the SDK attached
    /// `EncryptionInfo`). A plaintext event in an unencrypted room is `false`.
    pub was_encrypted: bool,
    /// Fail-closed tier of THIS MESSAGE at delivery time — the room's
    /// classification, downgraded per-message by [`delivery_tier`] when the
    /// event itself arrived without encryption (a homeserver can inject a
    /// plaintext event into an E2EE room; that message must never wear the
    /// [`SecurityTier::InternalE2ee`] badge). UI MUST badge the message with
    /// it and, for [`SecurityTier::BridgedExternal`], show the
    /// [`crate::disclosure`] copy.
    pub tier: SecurityTier,
}

/// Fail-closed **per-message** tier for a received event — the receive-path
/// mirror of [`MatrixMessenger::send_text`]'s `sent.encryption_info.is_none()`
/// belt-and-suspenders check. Pure and offline-testable.
///
/// A homeserver (or anyone it lets in) can inject a **plaintext** event into
/// a room that is classified [`SecurityTier::InternalE2ee`]; the room-level
/// classification alone would badge that injected message "E2EE (Postern)",
/// overstating its assurance. So: if the room tier is internal but the event
/// arrived without encryption (`was_encrypted == false` — the SDK attached no
/// `EncryptionInfo`, i.e. the event was not verified-decrypted), the
/// message's tier is downgraded to [`SecurityTier::BridgedExternal`] — warn,
/// never pretend. Everything else passes the room tier through unchanged.
///
/// HONEST LIMIT: this checks only encrypted-vs-plaintext arrival, not sender
/// device trust — cross-signing/verification is Phase 2 (see
/// [`PHASE1_REMAINING`]).
pub fn delivery_tier(room_tier: SecurityTier, was_encrypted: bool) -> SecurityTier {
    if room_tier == SecurityTier::InternalE2ee && !was_encrypted {
        return SecurityTier::BridgedExternal;
    }
    room_tier
}

/// One row of [`MatrixMessenger::room_list`]'s output.
///
/// **Phase-1 UNAUDITED scaffold.** `tier` is computed the same fail-closed
/// way as everywhere else in this module ([`Self::tier_of`] / [`classify_room`]
/// — encryption state + bridge-ghost scan); it is never defaulted to
/// [`SecurityTier::InternalE2ee`]. `name` is read purely from local sync
/// state ([`Room::name`], no I/O) and is `None` when the room has no
/// `m.room.name` and no computable fallback yet.
#[derive(Debug, Clone)]
pub struct RoomSummary {
    pub room_id: OwnedRoomId,
    pub name: Option<String>,
    pub tier: SecurityTier,
    pub is_direct: bool,
}

/// A minimal, restartable snapshot of a logged-in Matrix session — the
/// pieces [`MatrixMessenger::restore`] needs to make a process restart
/// resume the SAME Matrix device (same `user_id`/`device_id`/`access_token`)
/// instead of registering a fresh one via [`MatrixMessenger::login_password`]
/// / [`MatrixMessenger::login_password_persistent`].
///
/// Mirrors [`matrix_sdk::authentication::matrix::MatrixSession`]'s
/// `meta.user_id`, `meta.device_id`, and `tokens.access_token`, flattened
/// into one struct: this Phase-1 slice does not yet restore/rotate a
/// refresh token (see the HONEST CAVEAT on [`MatrixMessenger::restore`]).
///
/// # HONEST CAVEAT — `access_token` is a secret, held here in the clear
///
/// `access_token` is a bearer credential: whoever holds it can act as this
/// Matrix device (read/decrypt synced messages, send messages, and on some
/// homeserver configs more) until it is invalidated. `#[derive(Serialize,
/// Deserialize)]` here is for **plumbing** — turning this struct into bytes
/// a caller can hand to a store — it does **NOT** encrypt or otherwise
/// protect the token. Calling `serde_json::to_string` on a `SavedSession`
/// and writing the result straight to disk leaves that token in plaintext.
///
/// Persisting a `SavedSession` at rest MUST go through the sealed path:
/// [`SavedSession::seal_to`] wraps the blob with the workspace's hybrid
/// X25519+ML-KEM-1024 seal (`postern_courier`), and
/// [`SavedSession::open_sealed`] opens it — fail-closed on a wrong key or a
/// tampered blob. That covers the at-rest blob ONLY; the full honest scope
/// is [`SEALED_SESSION_LIMITS`] — read it before claiming anything.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SavedSession {
    pub user_id: OwnedUserId,
    pub device_id: OwnedDeviceId,
    pub access_token: String,
}

impl SavedSession {
    /// Seal this session for at-rest persistence: serialize to JSON (the
    /// intermediate plaintext is zeroized before returning, success or
    /// error) and wrap it with the workspace's hybrid **X25519 + ML-KEM-1024**
    /// seal ([`postern_courier::seal`]) to `recipient_public` (a
    /// [`postern_courier::generate_recipient`] hybrid public key). The
    /// returned bytes are [`postern_courier::SealedPayload::to_bytes`] wire
    /// format — hand them to [`Self::open_sealed`] to get the session back.
    ///
    /// # HONEST CAVEAT (see [`SEALED_SESSION_LIMITS`], machine-checked)
    ///
    /// Sealed-at-rest applies to the persisted `SavedSession` blob ONLY:
    /// the Megolm/Olm transport crypto remains classical Curve25519 (NOT
    /// post-quantum; harvest-now-decrypt-later applies), the SDK's sqlite
    /// store keeps only its own passphrase encryption (not PQ-wrapped),
    /// whoever holds the courier recipient secret can open the blob and act
    /// as this Matrix device, and the whole crate remains pre-release and
    /// UNAUDITED. Custody of the recipient secret is the CALLER's problem —
    /// wiring it into the Postern vault is the desktop layer's job, not
    /// done here. And like every courier seal: this encrypts to whatever
    /// public key it is given — authenticate the key out-of-band
    /// ([`postern_courier::key_fingerprint`]).
    ///
    /// # HONEST CAVEAT — residual copies in process memory
    ///
    /// The zeroize guarantee covers exactly ONE buffer: the intermediate
    /// JSON this method allocates. It does NOT cover (a) `self` itself —
    /// [`SavedSession::access_token`] is a plain `String`, not
    /// zeroize-on-drop, so the token stays in memory for the struct's
    /// lifetime and wherever the struct was cloned/moved from — nor
    /// (b) `serde_json`'s own internal allocations during encoding, which
    /// may leave transient copies of the token in freed heap memory. This
    /// is at-rest protection for the persisted blob, not an in-memory
    /// secrecy guarantee; closing the in-memory gap (a zeroizing token
    /// type) is stated Phase-1 follow-up work, not done here.
    pub fn seal_to(&self, recipient_public: &[u8]) -> Result<Vec<u8>, MatrixError> {
        // Zeroizing: the JSON carries the bearer token in the clear; wipe
        // the intermediate buffer on every exit path (including the `?`s).
        let plaintext = zeroize::Zeroizing::new(serde_json::to_vec(self)?);
        let sealed = postern_courier::seal(recipient_public, &plaintext)?;
        Ok(sealed.to_bytes())
    }

    /// Open a blob produced by [`Self::seal_to`] with the recipient's hybrid
    /// secret key. Fail-closed: a wrong/foreign recipient secret, a
    /// bit-flipped or truncated blob, or an unknown wire version all error
    /// (the courier AEAD authenticates the whole payload) — there is no
    /// partial or best-effort result. The decrypted intermediate JSON is
    /// zeroized before returning, success or error.
    ///
    /// The same HONEST CAVEATs as [`Self::seal_to`] apply — scope is the
    /// at-rest blob only ([`SEALED_SESSION_LIMITS`]), and the zeroize covers
    /// only the one intermediate JSON buffer: the returned [`SavedSession`]
    /// holds the token in a plain (non-zeroizing) `String`, and
    /// `serde_json`'s internal allocations during decoding may leave
    /// transient copies in freed heap memory.
    pub fn open_sealed(recipient_secret: &[u8], sealed: &[u8]) -> Result<Self, MatrixError> {
        let payload = postern_courier::SealedPayload::from_bytes(sealed)?;
        let plaintext = zeroize::Zeroizing::new(postern_courier::open(recipient_secret, &payload)?);
        Ok(serde_json::from_slice(&plaintext)?)
    }
}

/// The Phase-1 Postern Matrix client: login, sync, tier-gated E2EE send,
/// decrypted receive. See the module docs for the honest scope and the
/// not-yet list.
pub struct MatrixMessenger {
    client: Client,
}

impl MatrixMessenger {
    /// Log in to `homeserver_url` with username + password and return a ready
    /// client. Uses the SDK's default **in-memory** store (see module docs —
    /// persistence is Phase-1 remaining work), so every login is a fresh
    /// Matrix device with fresh device keys.
    pub async fn login_password(
        homeserver_url: &str,
        username: &str,
        password: &str,
        device_display_name: &str,
    ) -> Result<Self, MatrixError> {
        let client = Client::builder().homeserver_url(homeserver_url).build().await?;
        client
            .matrix_auth()
            .login_username(username, password)
            .initial_device_display_name(device_display_name)
            .send()
            .await?;
        Ok(Self { client })
    }

    /// Log in to `homeserver_url` with username + password, backed by the
    /// SDK's **sqlite store** at `store_path` instead of the default
    /// in-memory one (see the module docs' persistence bullet). Olm/Megolm
    /// sessions, sync tokens, and decryption/replay bookkeeping now survive
    /// process restart: re-logging in against the same `store_path` resumes
    /// the same Matrix device instead of registering a fresh one.
    ///
    /// `store_passphrase` encrypts the on-disk sqlite database at the SDK
    /// layer (matrix-sdk-sqlite, Apache-2.0, built on rusqlite, MIT — both
    /// permissive). HONEST CAVEAT: this is the SDK's own store encryption,
    /// **not yet wrapped by the Postern PQ vault** — that composition is
    /// still Phase-1 remaining work, not done here.
    pub async fn login_password_persistent(
        homeserver_url: &str,
        username: &str,
        password: &str,
        device_display_name: &str,
        store_path: impl AsRef<std::path::Path>,
        store_passphrase: &str,
    ) -> Result<Self, MatrixError> {
        let client = Client::builder()
            .homeserver_url(homeserver_url)
            .sqlite_store(store_path, Some(store_passphrase))
            .build()
            .await?;
        client
            .matrix_auth()
            .login_username(username, password)
            .initial_device_display_name(device_display_name)
            .send()
            .await?;
        Ok(Self { client })
    }

    /// Snapshot the current login as a [`SavedSession`], if logged in — the
    /// counterpart to [`Self::restore`]. `None` if this client never logged
    /// in (mirrors [`matrix_sdk::authentication::matrix::MatrixAuth::session`]
    /// returning `None` before login).
    ///
    /// See [`SavedSession`]'s HONEST CAVEAT: the returned value carries the
    /// live access token in the clear. Callers persisting it are on the
    /// hook for protecting it (encryption at rest is a stated follow-up,
    /// not done by this method).
    pub fn session(&self) -> Option<SavedSession> {
        let session = self.client.matrix_auth().session()?;
        Some(SavedSession {
            user_id: session.meta.user_id,
            device_id: session.meta.device_id,
            access_token: session.tokens.access_token,
        })
    }

    /// Rebuild a **persistent** (sqlite-store, see [`Self::login_password_persistent`])
    /// client at `store_path` and restore `session` into it, so a process
    /// restart resumes the SAME Matrix device — same `user_id`/`device_id`,
    /// same Olm/Megolm state already on disk under `store_path` — instead of
    /// [`Self::login_password`]/[`Self::login_password_persistent`]
    /// registering a fresh one.
    ///
    /// `store_passphrase` must be the SAME passphrase the store was created
    /// with (see [`Self::login_password_persistent`]'s HONEST CAVEAT: this is
    /// the SDK's own sqlite-store encryption, not yet wrapped by the Postern
    /// PQ vault).
    ///
    /// HONEST CAVEAT (do no network I/O, verify nothing): in matrix-sdk 0.18,
    /// [`matrix_sdk::authentication::matrix::MatrixAuth::restore_session`]
    /// only writes local client/session state (and locally activates the
    /// base client + spawns the local E2EE init task) — it makes **no
    /// request to the homeserver** and therefore does **not** verify that
    /// `session.access_token` is still valid there. An invalid/revoked token
    /// restores "successfully" here and only fails on the first real request
    /// (e.g. the next [`Self::sync_once`]). That is why the offline unit
    /// test below is explicitly labeled a SHAPE test: a fabricated
    /// `SavedSession` proves the plumbing (client rebuilds, SDK reports the
    /// restored identity back), never that it was ever a live, valid login.
    pub async fn restore(
        homeserver_url: &str,
        store_path: impl AsRef<std::path::Path>,
        store_passphrase: &str,
        session: SavedSession,
    ) -> Result<Self, MatrixError> {
        let client = Client::builder()
            .homeserver_url(homeserver_url)
            .sqlite_store(store_path, Some(store_passphrase))
            .build()
            .await?;
        let matrix_session = MatrixSession {
            meta: SessionMeta { user_id: session.user_id, device_id: session.device_id },
            tokens: SessionTokens { access_token: session.access_token, refresh_token: None },
        };
        client.matrix_auth().restore_session(matrix_session, RoomLoadSettings::default()).await?;
        Ok(Self { client })
    }

    /// Wrap an already-built [`matrix_sdk::Client`] (custom store, custom HTTP
    /// stack — the future `postern-tor` path — or an offline client in tests).
    pub fn with_client(client: Client) -> Self {
        Self { client }
    }

    /// The underlying SDK client, for what the slice doesn't wrap yet.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// The logged-in user, if any.
    pub fn user_id(&self) -> Option<&matrix_sdk::ruma::UserId> {
        self.client.user_id()
    }

    /// The logged-in device ID, if any — set by [`Self::login_password`],
    /// [`Self::login_password_persistent`], or [`Self::restore`].
    pub fn device_id(&self) -> Option<&DeviceId> {
        self.client.device_id()
    }

    /// Run one sync round-trip: pulls new events (decrypting E2EE ones),
    /// uploads this device's keys, and services the SDK's Olm to-device
    /// traffic (incoming `m.room_key` shares land here). Event handlers
    /// registered via [`Self::on_text_message`] fire during the call.
    pub async fn sync_once(&self) -> Result<(), MatrixError> {
        self.client.sync_once(SyncSettings::default()).await?;
        Ok(())
    }

    /// Start a **background** sync loop: repeated `client.sync_once` calls,
    /// waiting [`retry_backoff`] between consecutive failures, spawned onto
    /// the **current tokio runtime** via [`tokio::spawn`] — this method is
    /// therefore only callable from inside a tokio context (e.g.
    /// `#[tokio::main]` / `#[tokio::test]`), exactly like `tokio::spawn`
    /// itself. Event handlers registered via [`Self::on_text_message`] fire
    /// as syncs land, same as under [`Self::sync_once`]. On a *successful*
    /// sync the attempt counter resets to zero, so backoff only ever grows
    /// across a *consecutive* run of failures, never across an isolated blip.
    ///
    /// Returns a [`SyncLoopHandle`]; call [`SyncLoopHandle::stop`] to cancel
    /// it. Dropping the handle without calling `stop()` leaves the loop
    /// running in the background (it owns a cloned [`matrix_sdk::Client`],
    /// which is cheap — internally `Arc`-backed — to clone).
    ///
    /// **HONEST CAVEAT: this loop has NOT been run against a live homeserver
    /// by this crate's offline test suite.** The offline test below
    /// (`sync_loop_stop_cancels_promptly`) only proves `stop()` cancels a
    /// spawned loop within a tokio timeout, using
    /// `https://homeserver.invalid` with no login — that is a cancellation
    /// test, NOT a sync-correctness test. It does not prove the loop ever
    /// completes a real sync, retries correctly after a genuine homeserver
    /// hiccup, or survives a real long-poll cycle. That live proof is a
    /// `matrix_live` follow-up (see `tests/matrix_live.rs`), not this file.
    pub fn sync_loop(&self) -> SyncLoopHandle {
        let client = self.client.clone();
        let task = tokio::spawn(async move {
            let mut attempt: u32 = 0;
            loop {
                match client.sync_once(SyncSettings::default()).await {
                    Ok(_) => attempt = 0,
                    Err(_) => {
                        attempt = attempt.saturating_add(1);
                        tokio::time::sleep(retry_backoff(attempt)).await;
                    }
                }
            }
        });
        SyncLoopHandle { task }
    }

    /// Create a private, encrypted, direct room with `invitee` and send it —
    /// the ONLY room-creation path this crate exposes. Builds the request via
    /// the pure, offline-testable [`encrypted_dm_request`] (private
    /// visibility + `is_direct` + one `m.room.encryption` initial-state
    /// event) and hands it to the SDK. There is deliberately NO
    /// plaintext-room constructor on this crate's surface — mirrors the
    /// no-silent-downgrade rule at [`Self::send_text`]: no "create anyway"
    /// escape hatch.
    ///
    /// **Offline coverage only here**: this method's own network round-trip
    /// (`Client::create_room`) needs a live homeserver, so it is exercised by
    /// the `#[ignore]`d `matrix_live` integration test
    /// (`e2ee_text_roundtrip_between_two_accounts`), not by a unit test in
    /// this module. What IS offline-proven is the request it sends: see the
    /// `encrypted_dm_request_*` tests below.
    pub async fn create_encrypted_dm(&self, invitee: &UserId) -> Result<OwnedRoomId, MatrixError> {
        let request = encrypted_dm_request(invitee);
        let room = self.client.create_room(request).await?;
        Ok(room.room_id().to_owned())
    }

    /// Fail-closed tier of a known room (encryption state + bridge-ghost scan
    /// over joined/invited members). See [`classify_room`] for exactly what
    /// is — and is not yet — checked.
    pub async fn room_tier(&self, room_id: &RoomId) -> Result<SecurityTier, MatrixError> {
        let room = self
            .client
            .get_room(room_id)
            .ok_or_else(|| MatrixError::UnknownRoom(room_id.to_owned()))?;
        Self::tier_of(&room).await
    }

    async fn tier_of(room: &Room) -> Result<SecurityTier, MatrixError> {
        let state = room.latest_encryption_state().await?;
        let encryption = if state.is_encrypted() {
            RoomEncryption::Encrypted
        } else if state.is_unknown() {
            RoomEncryption::Unknown
        } else {
            RoomEncryption::NotEncrypted
        };
        let members = room.members(RoomMemberships::ACTIVE).await?;
        Ok(classify_room(
            encryption,
            members.iter().map(|m| m.user_id().as_str()),
            DEFAULT_BRIDGE_USER_PREFIXES,
        ))
    }

    /// **Phase-1 UNAUDITED scaffold — NOT booted against a live homeserver.**
    /// List every room the SDK's in-memory store currently knows about
    /// (joined/invited/left, whatever [`matrix_sdk::Client::rooms`] returns),
    /// stamping each with its fail-closed [`SecurityTier`] via [`Self::tier_of`]
    /// — the same reused, never-defaulted-to-internal classification path as
    /// [`Self::room_tier`] and the send gate.
    ///
    /// Names come from [`Room::name`], which reads the already-synced
    /// `m.room.name` (or a computed fallback) purely from local state — no
    /// network call. Against a fresh, un-logged-in client this always
    /// returns `Ok(vec![])` (there is nothing in the store to enumerate);
    /// the offline test below only proves that shape, not that the wrapper
    /// has ever spoken to a real homeserver. The live path stays the
    /// `#[ignore]`d `matrix_live` test.
    pub async fn room_list(&self) -> Result<Vec<RoomSummary>, MatrixError> {
        let mut summaries = Vec::new();
        for room in self.client.rooms() {
            let tier = Self::tier_of(&room).await?;
            let is_direct = room.is_direct().await.map_err(matrix_sdk::Error::from)?;
            summaries.push(RoomSummary {
                room_id: room.room_id().to_owned(),
                name: room.name(),
                tier,
                is_direct,
            });
        }
        Ok(summaries)
    }

    /// Send a text message into an **internal-tier** room. The SDK encrypts it
    /// with the room's Megolm session and — the piece this crate never had —
    /// distributes that session's key **Olm-encrypted to every recipient
    /// device** (`m.room_key` to-device events), querying/claiming device keys
    /// as needed.
    ///
    /// Tier gate (no silent downgrade): if the room's fail-closed
    /// classification is not [`SecurityTier::InternalE2ee`], this returns
    /// [`MatrixError::NotInternalE2ee`] and sends nothing. There is
    /// deliberately no "send anyway" flag on this API.
    pub async fn send_text(
        &self,
        room_id: &RoomId,
        body: &str,
    ) -> Result<OwnedEventId, MatrixError> {
        let room = self
            .client
            .get_room(room_id)
            .ok_or_else(|| MatrixError::UnknownRoom(room_id.to_owned()))?;
        let tier = Self::tier_of(&room).await?;
        if tier != SecurityTier::InternalE2ee {
            return Err(MatrixError::NotInternalE2ee { room: room_id.to_owned(), tier });
        }
        let sent = room.send(RoomMessageEventContent::text_plain(body)).await?;
        let event_id = sent.response.event_id;
        // Belt and suspenders: the SDK reports whether the event actually
        // went out Megolm-encrypted. On the internal tier that must ALWAYS
        // be the case; anything else is surfaced as a hard error.
        if sent.encryption_info.is_none() {
            return Err(MatrixError::SentUnencrypted { room: room_id.to_owned(), event: event_id });
        }
        Ok(event_id)
    }

    /// Register a callback for incoming text messages (fires during sync
    /// calls). Encrypted events are already Megolm-decrypted by the SDK;
    /// `was_encrypted` says whether E2EE actually happened, and `tier` is the
    /// **per-message** fail-closed tier at delivery time: the room's
    /// classification, run through [`delivery_tier`] — a plaintext event the
    /// homeserver injected into an E2EE room is downgraded to
    /// [`SecurityTier::BridgedExternal`] instead of wearing the room's
    /// internal badge (the receive-path mirror of [`Self::send_text`]'s
    /// `encryption_info` check). If classification itself errors, the message
    /// is stamped [`SecurityTier::BridgedExternal`] (warn, never pretend).
    ///
    /// NOTE (honest): replay/dedup bookkeeping is the SDK's, in whatever
    /// store the client was built with — in-memory under
    /// [`Self::login_password`] (lost on restart), on-disk sqlite under
    /// [`Self::login_password_persistent`] / [`Self::restore`].
    pub fn on_text_message(
        &self,
        callback: impl Fn(ReceivedText) + Send + Sync + 'static,
    ) -> matrix_sdk::event_handler::EventHandlerHandle {
        let callback = Arc::new(callback);
        self.client.add_event_handler(
            move |event: OriginalSyncRoomMessageEvent,
                  room: Room,
                  encryption_info: Option<EncryptionInfo>| {
                let callback = callback.clone();
                async move {
                    let MessageType::Text(text) = event.content.msgtype else { return };
                    let room_tier = Self::tier_of(&room)
                        .await
                        .unwrap_or(SecurityTier::BridgedExternal);
                    let was_encrypted = encryption_info.is_some();
                    // Per-message downgrade BEFORE the tier is attached to the
                    // delivered struct, so every consumer (UI badge, trail)
                    // sees it: a plaintext event injected into an E2EE room
                    // must not wear the InternalE2ee badge.
                    let tier = delivery_tier(room_tier, was_encrypted);
                    callback(ReceivedText {
                        room_id: room.room_id().to_owned(),
                        sender: event.sender,
                        event_id: event.event_id,
                        body: text.body,
                        was_encrypted,
                        tier,
                    });
                }
            },
        )
    }
}

/// Capped exponential backoff between consecutive `sync_once` failures in
/// [`MatrixMessenger::sync_loop`] — pure math, no I/O, no clock reads, and
/// therefore unit-testable without a network (see the `retry_backoff_*`
/// tests below). `attempt` is the 1-based count of consecutive failures (the
/// caller passes `1` for the first failure, `2` for the second in a row,
/// etc.); `0` is treated the same as `1` since there is no meaningful "zeroth"
/// backoff. Doubles from a 250ms floor, capped at 30s, so a homeserver outage
/// neither hammers the server with a retry storm nor leaves the client silent
/// for an unbounded stretch.
pub fn retry_backoff(attempt: u32) -> Duration {
    const BASE_MS: u64 = 250;
    const CAP_MS: u64 = 30_000;
    let attempt = attempt.max(1);
    // Shift capped at 16: 250ms << 16 is already ~16,384s, far past the 30s
    // cap, so anything beyond that would only risk an integer shift overflow
    // for no behavioral difference.
    let shift = (attempt - 1).min(16);
    let doubled_ms = BASE_MS.saturating_mul(1u64 << shift);
    Duration::from_millis(doubled_ms.min(CAP_MS))
}

/// Handle to a background sync loop started by [`MatrixMessenger::sync_loop`].
///
/// Dropping this handle WITHOUT calling [`Self::stop`] does NOT stop the
/// loop — the spawned task owns its own cloned [`matrix_sdk::Client`] and
/// keeps syncing in the background regardless of whether anything still
/// holds this handle. Always call `stop()` to shut it down.
pub struct SyncLoopHandle {
    task: tokio::task::JoinHandle<()>,
}

impl SyncLoopHandle {
    /// Cancel the sync loop and wait for the background task to actually
    /// stop, proving cancellation rather than merely requesting it.
    ///
    /// This aborts the task outright (`JoinHandle::abort`) rather than
    /// signalling it to wind down cooperatively: `sync_once`'s in-flight HTTP
    /// long-poll offers no fine-grained cancellation checkpoint to await
    /// through, so `abort()` is the only way to guarantee `stop()` resolves
    /// promptly regardless of what the loop happens to be doing (mid-sync,
    /// mid-backoff-sleep, or between iterations) when it is called. The
    /// awaited `JoinError` is always a cancellation in this path (we just
    /// aborted it ourselves) and is intentionally discarded — a caller asking
    /// to stop the loop does not want an error back about having stopped it.
    pub async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- classification: the fail-closed truth table (offline) ------------

    const NO_GHOSTS: [&str; 2] = ["@alice:postern.example", "@bob:postern.example"];

    #[test]
    fn encrypted_room_with_clean_members_is_internal() {
        let tier =
            classify_room(RoomEncryption::Encrypted, NO_GHOSTS, DEFAULT_BRIDGE_USER_PREFIXES);
        assert_eq!(tier, SecurityTier::InternalE2ee);
    }

    #[test]
    fn unencrypted_room_is_bridged_even_with_clean_members() {
        let tier =
            classify_room(RoomEncryption::NotEncrypted, NO_GHOSTS, DEFAULT_BRIDGE_USER_PREFIXES);
        assert_eq!(tier, SecurityTier::BridgedExternal);
    }

    #[test]
    fn unknown_encryption_state_fails_closed_to_bridged() {
        // "Sync didn't say" must NEVER look safe.
        let tier =
            classify_room(RoomEncryption::Unknown, NO_GHOSTS, DEFAULT_BRIDGE_USER_PREFIXES);
        assert_eq!(tier, SecurityTier::BridgedExternal);
    }

    #[test]
    fn encrypted_room_with_a_bridge_ghost_is_bridged() {
        // Encryption on the Matrix leg does not help: the bridge re-plaintexts.
        let members = ["@alice:postern.example", "@telegram_123456:bridge.example"];
        let tier =
            classify_room(RoomEncryption::Encrypted, members, DEFAULT_BRIDGE_USER_PREFIXES);
        assert_eq!(tier, SecurityTier::BridgedExternal);
    }

    #[test]
    fn bridge_bot_matches_too() {
        let members = ["@alice:postern.example", "@whatsappbot:bridge.example"];
        let tier =
            classify_room(RoomEncryption::Encrypted, members, DEFAULT_BRIDGE_USER_PREFIXES);
        assert_eq!(tier, SecurityTier::BridgedExternal);
    }

    #[test]
    fn empty_member_list_can_still_be_internal_if_encrypted() {
        // Membership not yet known but encryption provably on: internal per
        // the current (Phase-1) rule — device accounting tightens this in
        // Phase 2. The encryption gate is what fails closed today.
        let tier = classify_room(RoomEncryption::Encrypted, [], DEFAULT_BRIDGE_USER_PREFIXES);
        assert_eq!(tier, SecurityTier::InternalE2ee);
    }

    // ---- delivery_tier: per-message downgrade on the receive path ----------
    // Regression tests for the homeserver-injected-plaintext hole: before
    // `delivery_tier` existed, `on_text_message` stamped the ROOM's tier on
    // every message, so a plaintext event injected into an E2EE room was
    // badged InternalE2ee (was_encrypted=false, tier=InternalE2ee). These
    // pin the receive-path mirror of send_text's encryption_info check.

    #[test]
    fn encrypted_event_in_e2ee_room_keeps_internal_tier() {
        // The honest happy path: room internal, event actually arrived E2EE.
        assert_eq!(
            delivery_tier(SecurityTier::InternalE2ee, true),
            SecurityTier::InternalE2ee
        );
    }

    #[test]
    fn plaintext_event_in_e2ee_room_is_downgraded_not_badged_internal() {
        // THE regression: a homeserver-injected plaintext event in a room
        // classified InternalE2ee must be downgraded per-message — it must
        // NEVER wear the "E2EE (Postern)" badge. This assert fails against
        // the pre-fix behavior (room tier passed through unconditionally).
        assert_eq!(
            delivery_tier(SecurityTier::InternalE2ee, false),
            SecurityTier::BridgedExternal,
            "a plaintext event in an E2EE room must not be badged InternalE2ee"
        );
    }

    #[test]
    fn plaintext_room_tier_is_unchanged_by_delivery_tier() {
        // A bridged/plaintext room stays bridged regardless of how the
        // event arrived — no downgrade needed, and (belt and suspenders)
        // an encrypted event in a bridged room must never be UPGRADED.
        assert_eq!(
            delivery_tier(SecurityTier::BridgedExternal, false),
            SecurityTier::BridgedExternal
        );
        assert_eq!(
            delivery_tier(SecurityTier::BridgedExternal, true),
            SecurityTier::BridgedExternal,
            "delivery_tier must only ever downgrade, never upgrade"
        );
    }

    #[test]
    fn homeserver_metadata_limits_names_the_four_honest_leaks_and_the_tor_caveat() {
        // The founder-required claims must survive any future copy edit:
        // homeserver sees you exist/are online, the social graph, timing,
        // and the device list — and the Tor mitigation is honestly not
        // wired for this client yet, so this slice must not claim metadata
        // protection.
        let text = HOMESERVER_METADATA_LIMITS;
        assert!(text.contains("metadata"));
        assert!(
            text.contains("social graph") || text.contains("who"),
            "must name the social-graph / who-is-in-which-room leak"
        );
        assert!(
            text.contains("timing") || text.contains("when"),
            "must name the message-timing leak"
        );
        assert!(
            text.contains("not") && text.contains("Tor"),
            "must honestly say the Tor mitigation is NOT wired for the matrix client yet"
        );
    }

    #[test]
    fn phase1_remaining_names_every_open_caveat() {
        // Same machine-check pattern as HOMESERVER_METADATA_LIMITS above:
        // the remaining-work claims must survive any future copy edit until
        // the code actually does each thing — at which point the item moves
        // to the done side and THIS test is updated in the same commit.
        let text = PHASE1_REMAINING;
        assert!(
            text.contains("Tor") && text.contains("NOT wired"),
            "must say Tor is not wired for the matrix client"
        );
        assert!(
            text.contains("no verification") && text.contains("cross-signing"),
            "must say verification/cross-signing does not exist yet (Phase 2)"
        );
        assert!(text.contains("UNAUDITED"), "must keep the UNAUDITED label");
        assert!(
            text.contains("NOT post-quantum"),
            "must say the Megolm/Olm crypto is classical, not post-quantum"
        );
        // Item (4) moved half-way in the seal-at-rest commit and the wording
        // must say EXACTLY what changed — the old blanket "the SavedSession
        // access token is NOT wrapped" claim must be gone (the token IS now
        // sealable), while the still-open halves stay stated.
        assert!(
            text.contains("access token") && text.contains("SEALABLE"),
            "must say the SavedSession access token is now sealable at rest"
        );
        assert!(
            text.contains("seal_to") && text.contains("open_sealed"),
            "must name the sealed-session API so callers can find it"
        );
        assert!(
            text.contains("hybrid X25519+ML-KEM-1024") && text.contains("postern-courier"),
            "must say exactly which seal wraps the blob (hybrid PQ via postern-courier)"
        );
        assert!(
            text.contains("caller-opt-in") && text.contains("plaintext"),
            "must say sealing is opt-in — plain serde still emits the token in plaintext"
        );
        assert!(
            text.contains("recipient secret") && text.contains("caller"),
            "must say custody of the courier recipient secret is the caller's"
        );
        assert!(
            text.contains("act as this Matrix device"),
            "must say the recipient-secret holder can act as this Matrix device"
        );
        assert!(
            text.contains("desktop layer"),
            "must say vault integration is the desktop layer's job, not done here"
        );
        assert!(
            text.contains("sqlite store passphrase") && text.contains("NOT wrapped"),
            "must say the sqlite store passphrase remains SDK-layer-only, not PQ-vault-wrapped"
        );
        assert!(
            !text.contains("the sqlite store passphrase and the SavedSession access token are NOT wrapped"),
            "the old blanket both-halves-open claim must be gone — the token half landed"
        );
        assert!(
            text.contains("never booted in CI"),
            "must say the live paths are not run in CI"
        );
        assert!(
            text.contains("not a functional messenger"),
            "must not let the crate claim to be a functional messenger product"
        );
    }

    #[test]
    fn bridge_prefixes_are_well_formed() {
        assert!(!DEFAULT_BRIDGE_USER_PREFIXES.is_empty());
        for p in DEFAULT_BRIDGE_USER_PREFIXES {
            assert!(p.starts_with('@'), "prefix {p:?} must match a Matrix user ID");
            assert!(p.len() > 2);
        }
    }

    // ---- encrypted_dm_request: the pure builder (offline, no homeserver) --

    #[test]
    fn encrypted_dm_request_is_private_direct_and_carries_exactly_one_encryption_event() {
        let invitee = matrix_sdk::ruma::user_id!("@bob:postern.example");
        let request = encrypted_dm_request(invitee);

        assert_eq!(request.visibility, Visibility::Private);
        assert!(request.is_direct, "a DM room must be marked is_direct");
        assert_eq!(request.invite, vec![invitee.to_owned()], "invitee must be invited");

        assert_eq!(
            request.initial_state.len(),
            1,
            "exactly one initial_state event — no more, no less"
        );
        let raw = &request.initial_state[0];
        assert_eq!(
            raw.get_field::<String>("type").ok().flatten().as_deref(),
            Some("m.room.encryption"),
            "the single initial_state event must be m.room.encryption"
        );
    }

    #[test]
    fn encrypted_dm_request_invites_exactly_the_given_invitee() {
        let invitee = matrix_sdk::ruma::user_id!("@carol:postern.example");
        let request = encrypted_dm_request(invitee);
        assert_eq!(request.invite.len(), 1);
        assert_eq!(request.invite[0], invitee);
    }

    // ---- client plumbing that works offline --------------------------------

    /// Building a client against an explicit homeserver URL does no I/O, so
    /// the wrapper is testable offline: not logged in, rooms unknown, and the
    /// send path refuses cleanly instead of panicking.
    #[tokio::test]
    async fn offline_client_wraps_and_send_refuses_unknown_room() {
        let client = Client::builder()
            .homeserver_url("https://homeserver.invalid")
            .build()
            .await
            .expect("building with an explicit URL needs no network");
        let messenger = MatrixMessenger::with_client(client);
        assert!(messenger.user_id().is_none(), "no login happened");

        let room_id = matrix_sdk::ruma::room_id!("!nosuchroom:homeserver.invalid");
        match messenger.send_text(room_id, "hello").await {
            Err(MatrixError::UnknownRoom(r)) => assert_eq!(r, room_id),
            other => panic!("expected UnknownRoom, got {other:?}"),
        }
        match messenger.room_tier(room_id).await {
            Err(MatrixError::UnknownRoom(_)) => {}
            other => panic!("expected UnknownRoom, got {other:?}"),
        }
    }

    /// Registering the receive handler must not require a login or network.
    #[tokio::test]
    async fn handler_registration_is_offline() {
        let client = Client::builder()
            .homeserver_url("https://homeserver.invalid")
            .build()
            .await
            .unwrap();
        let messenger = MatrixMessenger::with_client(client);
        let _handle = messenger.on_text_message(|_msg| {});
    }

    /// **Phase-1 UNAUDITED scaffold, offline-only.** Building a client
    /// against an explicit homeserver URL with no login does no network I/O,
    /// so `room_list` must enumerate the SDK's (empty) in-memory store and
    /// return cleanly — proving the wrapper compiles and runs its fail-closed
    /// `tier_of`/`classify_room` path without ever having synced against a
    /// real homeserver. This is NOT a test that room_list has been booted
    /// live; that remains the `#[ignore]`d `matrix_live` test.
    #[tokio::test]
    async fn room_list_is_offline_and_empty_before_any_sync() {
        let client = Client::builder()
            .homeserver_url("https://homeserver.invalid")
            .build()
            .await
            .expect("building with an explicit URL needs no network");
        let messenger = MatrixMessenger::with_client(client);
        assert!(messenger.user_id().is_none(), "no login happened");

        let rooms = messenger.room_list().await;
        assert!(rooms.is_ok(), "room_list must not error on a fresh, un-logged-in client");
        assert!(
            rooms.unwrap().is_empty(),
            "a client that never synced has no rooms in its store yet"
        );
    }

    /// **Phase-1 UNAUDITED scaffold-shape test — the store is built and
    /// never synced live.** Building a `Client` with an explicit homeserver
    /// URL and `.sqlite_store(path, Some(passphrase))` does no network I/O
    /// (login is what would talk to a homeserver, and this test stops one
    /// step short of that), so this proves only: (1) the sqlite-store build
    /// path compiles and returns `Ok`, and (2) the SDK actually created
    /// sqlite database files on disk under `store_path` — i.e. that
    /// `login_password_persistent`'s store wiring is real, not that a login
    /// or sync has ever happened against a live homeserver. That remains the
    /// `#[ignore]`d `matrix_live` test.
    #[tokio::test]
    async fn persistent_client_creates_sqlite_store_files_offline() {
        let store_dir = tempfile::tempdir().expect("tempdir");

        let client = Client::builder()
            .homeserver_url("https://homeserver.invalid")
            .sqlite_store(store_dir.path(), Some("test-passphrase-not-a-secret"))
            .build()
            .await
            .expect("building with an explicit URL + local sqlite store needs no network");
        let messenger = MatrixMessenger::with_client(client);
        assert!(messenger.user_id().is_none(), "no login happened — build-only");

        // The store directory must now actually contain sqlite files: proof
        // the `sqlite_store(...)` wiring is real, not a no-op.
        let has_sqlite_file = std::fs::read_dir(store_dir.path())
            .expect("store dir must exist and be readable")
            .filter_map(|entry| entry.ok())
            .any(|entry| {
                entry
                    .path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| ext == "sqlite3" || ext == "db" || ext == "sqlite")
                    .unwrap_or(false)
            });
        assert!(
            has_sqlite_file,
            "expected sqlite store file(s) under {:?}, found: {:?}",
            store_dir.path(),
            std::fs::read_dir(store_dir.path())
                .unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.file_name())
                .collect::<Vec<_>>()
        );
    }

    // ---- retry_backoff: pure math, no network, no clock -------------------

    #[test]
    fn retry_backoff_is_monotone_non_decreasing() {
        let mut previous = retry_backoff(1);
        for attempt in 2..200u32 {
            let current = retry_backoff(attempt);
            assert!(
                current >= previous,
                "backoff must never shrink as attempts climb: attempt {attempt} gave \
                 {current:?}, attempt {} gave {previous:?}",
                attempt - 1
            );
            previous = current;
        }
    }

    #[test]
    fn retry_backoff_is_capped() {
        const CAP: Duration = Duration::from_secs(30);
        // Comfortably past where the exponential would blow through the cap
        // (2^16 doublings of a 250ms base already exceeds it), and far enough
        // to also probe for integer-overflow panics at extreme attempt counts.
        for attempt in [17, 32, 64, 1_000, u32::MAX / 2, u32::MAX] {
            let backoff = retry_backoff(attempt);
            assert!(backoff <= CAP, "attempt {attempt} gave {backoff:?}, expected <= {CAP:?}");
        }
    }

    #[test]
    fn retry_backoff_grows_from_a_small_floor() {
        let first = retry_backoff(1);
        assert!(first >= Duration::from_millis(100), "first backoff {first:?} is implausibly small");
        assert!(first <= Duration::from_secs(2), "first backoff {first:?} is implausibly large");
        assert!(retry_backoff(4) > first, "backoff must actually grow across a few failures");
    }

    #[test]
    fn retry_backoff_treats_attempt_zero_like_attempt_one() {
        // There is no meaningful "zeroth" backoff; callers always pass a
        // 1-based consecutive-failure count, but the function must not panic
        // or behave surprisingly if handed 0.
        assert_eq!(retry_backoff(0), retry_backoff(1));
    }

    // ---- sync_loop / SyncLoopHandle::stop: cancellation, not sync ---------

    /// **Cancellation proof, NOT a sync-correctness test — offline only.**
    /// `https://homeserver.invalid` never resolves and no login happens, so
    /// this proves only that a `sync_loop()` background task, once spawned,
    /// can be told to stop and `stop()` actually resolves — i.e. the task is
    /// gone, not just "asked nicely" — within a bounded tokio timeout. It
    /// does NOT prove the loop ever completes a real sync, retries correctly
    /// after a genuine homeserver hiccup, or survives a real long-poll cycle;
    /// that live proof is a `matrix_live` follow-up, not this test.
    #[tokio::test]
    async fn sync_loop_stop_cancels_promptly() {
        let client = Client::builder()
            .homeserver_url("https://homeserver.invalid")
            .build()
            .await
            .expect("building with an explicit URL needs no network");
        let messenger = MatrixMessenger::with_client(client);

        let handle = messenger.sync_loop();

        tokio::time::timeout(Duration::from_secs(5), handle.stop())
            .await
            .expect(
                "stop() must resolve within 5s — this proves prompt cancellation, \
                 not that any sync ever succeeded",
            );
    }

    // ---- SavedSession / MatrixMessenger::{session, restore} ---------------

    /// `SavedSession` must round-trip through `serde_json` byte-for-byte
    /// (field-for-field): this is the plumbing [`Self::restore`]'s caller
    /// relies on to persist and later reload a session. Does NOT touch the
    /// HONEST CAVEAT on [`SavedSession`] (that the token is unencrypted) —
    /// this only proves the (de)serialization shape is correct.
    #[test]
    fn saved_session_round_trips_through_serde_json() {
        let original = SavedSession {
            user_id: matrix_sdk::ruma::user_id!("@alice:homeserver.invalid").to_owned(),
            device_id: matrix_sdk::ruma::owned_device_id!("FABRICATEDDEVICE"),
            access_token: "fabricated-access-token-not-a-real-secret".to_owned(),
        };

        let json = serde_json::to_string(&original).expect("SavedSession must serialize");
        let restored: SavedSession =
            serde_json::from_str(&json).expect("SavedSession must deserialize");

        assert_eq!(restored, original, "round trip through serde_json must be lossless");
    }

    /// **Shape test — offline, fabricated token, proves plumbing only.**
    /// `matrix_auth().restore_session(...)` does no network I/O in
    /// matrix-sdk 0.18 (see [`Self::restore`]'s HONEST CAVEAT: it only
    /// writes local client/session state), so this test builds a brand-new
    /// persistent (sqlite-store) client against `https://homeserver.invalid`
    /// and restores a FABRICATED `SavedSession` — a token that was never
    /// issued by any real homeserver — into it. It proves only that:
    /// (1) [`MatrixMessenger::restore`] rebuilds a persistent client and (2)
    /// afterward the SDK reports the restored identity back via
    /// [`MatrixMessenger::user_id`] / [`MatrixMessenger::device_id`].
    ///
    /// It proves NOTHING about a live restore against a real homeserver —
    /// no request was ever sent, so an invalidated/wrong/expired token would
    /// pass this test identically. That live proof remains the `#[ignore]`d
    /// `matrix_live` test.
    #[tokio::test]
    async fn restore_shape_reports_the_fabricated_identity_offline() {
        let store_dir = tempfile::tempdir().expect("tempdir");
        let user_id = matrix_sdk::ruma::user_id!("@bob:homeserver.invalid").to_owned();
        let device_id = matrix_sdk::ruma::owned_device_id!("FABRICATEDDEVICE2");
        let fabricated = SavedSession {
            user_id: user_id.clone(),
            device_id: device_id.clone(),
            access_token: "fabricated-access-token-never-issued-by-any-homeserver".to_owned(),
        };

        let messenger = MatrixMessenger::restore(
            "https://homeserver.invalid",
            store_dir.path(),
            "test-passphrase-not-a-secret",
            fabricated,
        )
        .await
        .expect("restore_session does no network I/O — must succeed offline");

        assert_eq!(
            messenger.user_id(),
            Some(user_id.as_ref()),
            "user_id() must report the restored (fabricated) identity, not None"
        );
        assert_eq!(
            messenger.device_id(),
            Some(device_id.as_ref()),
            "device_id() must report the restored (fabricated) device, not None"
        );

        // `session()` must hand the same three fields back out — the
        // save/restore round trip through the live client, not just the
        // struct.
        let saved_back = messenger.session().expect("a restored client must report a session");
        assert_eq!(saved_back.user_id, user_id);
        assert_eq!(saved_back.device_id, device_id);
        assert_eq!(saved_back.access_token, "fabricated-access-token-never-issued-by-any-homeserver");
    }

    // ---- SavedSession::{seal_to, open_sealed}: PQ-sealed at rest -----------
    // All offline: postern-courier's default build is the pure crypto seal
    // (no arti, no network). Fabricated token throughout — never a real one.

    fn fabricated_session() -> SavedSession {
        SavedSession {
            user_id: matrix_sdk::ruma::user_id!("@alice:homeserver.invalid").to_owned(),
            device_id: matrix_sdk::ruma::owned_device_id!("FABRICATEDDEVICE"),
            access_token: "fabricated-access-token-not-a-real-secret".to_owned(),
        }
    }

    /// The happy path: seal to a hybrid recipient key, open with the matching
    /// secret, get the identical session back — lossless, field for field.
    #[test]
    fn sealed_session_round_trips_losslessly() {
        let recipient = postern_courier::generate_recipient();
        let original = fabricated_session();

        let sealed = original.seal_to(&recipient.public).expect("seal_to must succeed");
        assert!(
            !sealed.windows(original.access_token.len()).any(|w| w == original.access_token.as_bytes()),
            "the sealed blob must not contain the bearer token in plaintext"
        );

        let opened = SavedSession::open_sealed(&recipient.secret, &sealed)
            .expect("open_sealed with the matching secret must succeed");
        assert_eq!(opened, original, "seal/open round trip must be lossless");
    }

    /// Fail-closed: a blob sealed to one recipient must NOT open with a
    /// different recipient's secret — wrong key errors, never a garbled or
    /// partial session.
    #[test]
    fn sealed_session_refuses_the_wrong_recipient_secret() {
        let intended = postern_courier::generate_recipient();
        let attacker = postern_courier::generate_recipient();

        let sealed = fabricated_session().seal_to(&intended.public).expect("seal_to");

        match SavedSession::open_sealed(&attacker.secret, &sealed) {
            Err(MatrixError::SessionSeal(_)) => {}
            Ok(_) => panic!("a foreign recipient secret must never open the blob"),
            Err(other) => panic!("expected the courier seal to refuse, got {other:?}"),
        }
    }

    /// Fail-closed: any single bit flipped anywhere in the sealed blob makes
    /// `open_sealed` error (the courier AEAD authenticates the whole payload;
    /// the version byte and KEM ct are transcript-bound). Never a silently
    /// corrupted session.
    #[test]
    fn sealed_session_refuses_a_bit_flipped_blob() {
        let recipient = postern_courier::generate_recipient();
        let sealed = fabricated_session().seal_to(&recipient.public).expect("seal_to");

        // Probe a spread of positions: the version byte, inside the hybrid
        // encapsulation, the nonce, and the AEAD ciphertext/tag tail.
        let probes = [0, 1, sealed.len() / 2, sealed.len() - 2, sealed.len() - 1];
        for &pos in &probes {
            let mut tampered = sealed.clone();
            tampered[pos] ^= 0x01;
            assert!(
                SavedSession::open_sealed(&recipient.secret, &tampered).is_err(),
                "a bit flip at byte {pos} must make open_sealed fail closed"
            );
        }

        // Truncation fails closed too.
        assert!(
            SavedSession::open_sealed(&recipient.secret, &sealed[..sealed.len() / 2]).is_err(),
            "a truncated blob must fail closed"
        );
        assert!(
            SavedSession::open_sealed(&recipient.secret, &[]).is_err(),
            "an empty blob must fail closed"
        );
    }

    #[test]
    fn sealed_session_limits_names_every_honest_caveat() {
        // Same machine-check pattern as HOMESERVER_METADATA_LIMITS /
        // PHASE1_REMAINING: the sealed-session honesty claims must survive
        // any future copy edit.
        let text = SEALED_SESSION_LIMITS;
        assert!(
            text.contains("SavedSession blob ONLY"),
            "must scope the sealing claim to the persisted blob only"
        );
        assert!(
            text.contains("classical Curve25519") && text.contains("NOT post-quantum"),
            "must say the Megolm/Olm transport crypto stays classical"
        );
        assert!(
            text.contains("harvest-now-decrypt-later"),
            "must keep the harvest-now-decrypt-later warning"
        );
        assert!(
            text.contains("sqlite store") && text.contains("not PQ-wrapped"),
            "must say the sqlite store keeps only its own passphrase encryption"
        );
        assert!(
            text.contains("recipient secret") && text.contains("act as this Matrix device"),
            "must say the recipient-secret holder can open the blob and act as this device"
        );
        assert!(
            text.contains("NOT an in-memory secrecy boundary") && text.contains("plain") && text.contains("String"),
            "must say the in-process SavedSession token is a plain String — \
             only the intermediate JSON buffer is zeroized"
        );
        assert!(text.contains("UNAUDITED"), "must keep the UNAUDITED label");
    }

    // ---- MatrixError: the boxed-Build size fix ------------------------------

    /// Regression pin for the `clippy::result_large_err` fix: `ClientBuildError`
    /// (>=160 bytes) is boxed inside [`MatrixError::Build`], so a
    /// `Result<_, MatrixError>` — e.g. from [`SavedSession::seal_to`] /
    /// [`SavedSession::open_sealed`] — stays within clippy's 128-byte
    /// large-err threshold. If a future variant regrows the enum, this fails
    /// before clippy does.
    #[test]
    fn matrix_error_stays_small_enough_for_result() {
        let size = std::mem::size_of::<MatrixError>();
        assert!(
            size <= 128,
            "MatrixError is {size} bytes — exceeds clippy::result_large_err's \
             128-byte threshold; box the offending variant's payload"
        );
    }

    /// The boxed variant must stay `?`-compatible: `From<ClientBuildError>`
    /// exists (hand-written, since `#[from]` cannot box) and lands in
    /// [`MatrixError::Build`] with the message text preserved through the
    /// `Box`'s `Display` passthrough.
    #[tokio::test]
    async fn client_build_error_converts_into_boxed_build_variant() {
        // The only way to obtain a real ClientBuildError offline: an invalid
        // homeserver URL fails in `build()` before any network I/O.
        let build_err = Client::builder()
            .homeserver_url("not a url at all")
            .build()
            .await
            .expect_err("an unparsable homeserver URL must fail the build");
        let matrix_err = MatrixError::from(build_err);
        match &matrix_err {
            MatrixError::Build(boxed) => {
                assert!(
                    matrix_err.to_string().starts_with("building matrix client failed:"),
                    "Display must keep the Build message prefix, got: {matrix_err}"
                );
                // The source chain survives the boxing (#[source] on Box).
                let _: &ClientBuildError = boxed;
                assert!(
                    std::error::Error::source(&matrix_err).is_some(),
                    "the boxed ClientBuildError must remain the error's source"
                );
            }
            other => panic!("expected MatrixError::Build, got {other:?}"),
        }
    }
}
