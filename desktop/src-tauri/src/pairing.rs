// SPDX-License-Identifier: MIT OR Apache-2.0
//! Phone-as-signer — the **DESKTOP REQUESTER** side (v1: wallet-LOGIN).
//!
//! This is the terminal end of the Postern Mobile⟷Desktop integration. The
//! desktop **holds no wallet key**. It runs the QR + SAS pairing ceremony against
//! a phone, composes a wallet-**login** challenge, asks the paired phone to sign
//! it, and records the outcome as a scoped, expiring, revocable
//! [`postern_policy`] grant.
//!
//! ## Unified on ONE wire (this is the whole point)
//!
//! Earlier this module REIMPLEMENTED the requester on a different stack
//! (`postern-courier` + `postern-seal-companion` + `postern-consiglio-auth`)
//! with a *scaffold* SAS derived from the public anchors. That could never
//! interoperate with the phone, which speaks the two SHIPPED crates. This
//! version **consumes** them instead, so the desktop and
//! [`postern_mobile_signer`] derive the **same** SAS and sign the **same** bytes:
//!
//! - [`postern_pairing`] drives the ceremony: a QR-pinned **ephemeral** anchor
//!   (X25519‖ML-KEM-1024) and the crate's **KEM-bound** 6-digit SAS — the REAL
//!   MITM tripwire (an active relay must re-encapsulate → a different session key
//!   → a different SAS → the human aborts). It also yields the live, forward-
//!   secret, replay-guarded [`postern_pairing::Channel`] every request rides.
//! - [`postern_signer_protocol`]'s [`DesktopRequester`] composes the
//!   `SignRequest` (fresh nonce + monotonic counter + session binding) and matches
//!   the returned `Approval` — the **exact wire types** the phone decodes.
//!
//! HONESTY / RAILS (restated so the UI cannot round it up):
//! - The desktop holds **no keys**. The only secret it ever mints is a *per-
//!   session ephemeral channel keypair* inside [`postern_pairing`] — never a wallet
//!   seed, never persisted. The wallet key never crosses the wire; only the
//!   signature/approval comes back (structurally — the protocol's wire types have
//!   no key field).
//! - This is **software**, **unaudited**, **scaffold**. It is **not** a hardware
//!   wallet. Pairing authenticates a *device key on your say-so*, not that the
//!   peer software is genuine. The QR + KEM-SAS check is **mandatory and fail-
//!   closed**: no [`PairingRecord`]/channel persists unless the human confirmed
//!   the SAS.
//! - Software signing ≠ hardware. **Local-first, no cloud**: nothing here contacts
//!   a server; the LAN hint is the only network coordinate and is broadcast to the
//!   subnet (a metadata leak the UI discloses). The coin (BLCH) is not a security.

use std::sync::Mutex;

use postern_pairing::pairing::{DesktopPending, SasConfirm};
use postern_pairing::{Channel as PairingChannel, Frame, Pairing, PairingInit, PairingRecord};
use postern_policy::{Decision, EnforcementMode, Expiry, Revocation};
use postern_signer_protocol::channel::Channel as ProtocolChannel;
use postern_signer_protocol::{
    fresh_nonce, DesktopRequester, LoginChallenge, ProtocolError, SentRequest, LOGIN_DOMAIN,
};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

/// Wall-clock unix seconds.
fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

/// The desktop is **keyless**: it has no long-term wallet/identity key to pin.
/// The phone TOFU-pins this constant as the "terminal identity"; the REAL per-
/// session authentication is the QR-pinned ephemeral anchor + the KEM-bound SAS,
/// re-run each pairing. Documented so no one mistakes it for an attested identity.
const DESKTOP_KEYLESS_IDENTITY: &[u8] = b"postern-desktop:keyless:v1";

/// A short display fingerprint (first 8 bytes as hex) of an opaque key/binding.
fn short_fingerprint(bytes: &[u8]) -> String {
    let n = bytes.len().min(8);
    hex::encode(&bytes[..n])
}

// ───────────────────────────────────────────────────────────────────────────
// A one-shot signer-protocol Channel.
//
// `DesktopRequester` is written against `postern_signer_protocol::channel::Channel`
// (send/recv opaque frames). Our two Tauri commands split the flow across separate
// invocations (compose+send in `login_request`, receive+match in `login_complete`),
// so we drive the requester over this in-memory capture channel and hand the
// resulting protocol frame to / from the REAL paired `postern_pairing::Channel`
// (seal on the way out, open on the way in) — exactly the seam
// `postern_mobile_signer::PairedSignerChannel` implements for a live socket.
// ───────────────────────────────────────────────────────────────────────────
#[derive(Default)]
struct CaptureChannel {
    outbox: Option<Vec<u8>>,
    inbox: Option<Vec<u8>>,
}

impl CaptureChannel {
    fn with_inbox(frame: Vec<u8>) -> Self {
        CaptureChannel { outbox: None, inbox: Some(frame) }
    }
}

impl ProtocolChannel for CaptureChannel {
    type Error = ProtocolError;

    fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        self.outbox = Some(frame.to_vec());
        Ok(())
    }

    fn recv(&mut self) -> Result<Vec<u8>, Self::Error> {
        self.inbox
            .take()
            .ok_or_else(|| ProtocolError::BadFrame("no protocol frame available".into()))
    }
}

// ───────────────────────────────────────────────────────────────────────────
// State.
// ───────────────────────────────────────────────────────────────────────────

/// The in-progress pairing: either anchored (QR emitted, awaiting the phone's
/// `PairingInit`) or confirming (SAS derived from the KEM shared secret, awaiting
/// the human's fail-closed confirm/reject). Mirrors the crate's own state machine.
enum Pending {
    Anchored { pending: DesktopPending },
    Confirming { confirm: SasConfirm, sas: String },
}

/// A confirmed pairing: the crate's [`PairingRecord`] (TOFU peer pin + forward-
/// secret session root) plus the live paired [`PairingChannel`] and this session's
/// [`DesktopRequester`] (monotonic counter). No wallet material anywhere.
struct PairedDevice {
    id: u64,
    nickname: String,
    record: PairingRecord,
    channel: PairingChannel,
    requester: DesktopRequester,
    sas: String,
    paired_at: i64,
    rev: Revocation,
}

/// An outstanding wallet-login sign-request the desktop composed via
/// [`DesktopRequester`]. `sent` carries the session/nonce/counter and the exact
/// digest the phone must sign — used to match the `Approval` and to VERIFY the
/// returned signature (fail-closed) before any grant is minted.
struct SignReq {
    id: u64,
    pairing_id: u64,
    org: String,
    user: String,
    #[allow(dead_code)]
    challenge: LoginChallenge,
    sent: SentRequest,
    #[allow(dead_code)]
    created: i64,
    status: &'static str,
}

/// A scoped, expiring, revocable consent grant (design §3.3) — a
/// `postern-policy` grant with a required future RFC-3339 expiry, re-evaluated
/// fail-closed at each list.
struct Grant {
    id: u64,
    scope: String,
    subject: String,
    org: String,
    expiry_raw: String,
    created: i64,
    rev: Revocation,
}

#[derive(Default)]
pub struct PairInner {
    pending: Option<Pending>,
    pairings: Vec<PairedDevice>,
    grants: Vec<Grant>,
    requests: Vec<SignReq>,
    seq: u64,
}

impl PairInner {
    fn next_id(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }
}

/// Tauri-managed pairing state. Scaffold: in-memory only (nothing is persisted to
/// disk — the UI discloses that pairings do not survive a restart yet).
#[derive(Default)]
pub struct PairState(pub Mutex<PairInner>);

// ───────────────────────────────────────────────────────────────────────────
// Commands — the ceremony.
// ───────────────────────────────────────────────────────────────────────────

/// Begin pairing: [`Pairing::begin_desktop`] mints a fresh **ephemeral** hybrid-PQ
/// anchor + nonce and emits the QR the phone scans. No wallet key is touched.
/// Replaces any prior pending ceremony. `nickname` labels the phone in the paired
/// list. Returns the QR (hex-encoded, self-describing) and the anchor fingerprint.
#[tauri::command]
pub fn pair_begin(
    state: tauri::State<PairState>,
    lan_hint: String,
    nickname: String,
) -> Result<Value, String> {
    let lan_hint = {
        let t = lan_hint.trim();
        if t.is_empty() { "mdns://_postern._tcp.local".to_string() } else { t.to_string() }
    };
    let nickname = {
        let t = nickname.trim();
        if t.is_empty() { "phone".to_string() } else { t.to_string() }
    };

    // The crate generates the ephemeral anchor internally; the QR carries the full
    // anchor pubkey + nonce + LAN hint + the (keyless) terminal identity.
    let (pending, qr) =
        Pairing::begin_desktop(nickname, lan_hint.clone(), DESKTOP_KEYLESS_IDENTITY.to_vec());
    let fingerprint = short_fingerprint(qr.anchor_public.as_slice());
    let binding = short_fingerprint(pending.channel_binding());
    let qr_hex = qr.to_hex();

    let mut inner = state.0.lock().unwrap();
    inner.pending = Some(Pending::Anchored { pending });
    Ok(json!({
        "qr": qr_hex,
        "fingerprint": fingerprint,
        "channelBinding": binding,
        "lanHint": lan_hint,
        "note": "Ephemeral channel anchor only — no wallet key exists on this device. \
                 The phone scans this QR, runs the ML-KEM-1024‖X25519 handshake, and \
                 returns its PairingInit; call pair_respond with it to derive the SAS.",
    }))
}

/// Receive the phone's `PairingInit` (hex: ML-KEM ct ‖ X25519 eph pk ‖ custodian
/// identity, delivered over the LAN leg) and [`DesktopPending::accept`] it:
/// decapsulate to the shared session key and derive the **KEM-bound** 6-digit SAS.
/// The SAS is returned for the human to compare on both screens. Nothing is
/// persisted yet — [`pair_confirm`] is the fail-closed gate.
#[tauri::command]
pub fn pair_respond(state: tauri::State<PairState>, pairing_init_hex: String) -> Result<Value, String> {
    let init_bytes = hex::decode(pairing_init_hex.trim())
        .map_err(|_| "PairingInit is not valid hex".to_string())?;
    let init = PairingInit::from_bytes(&init_bytes).map_err(|e| e.to_string())?;

    let mut inner = state.0.lock().unwrap();
    match inner.pending.take() {
        Some(Pending::Anchored { pending }) => {
            // `accept` consumes the DesktopPending: decapsulate → session key → SAS.
            let confirm = pending.accept(&init).map_err(|e| e.to_string())?;
            let sas = confirm.sas().digits();
            inner.pending = Some(Pending::Confirming { confirm, sas: sas.clone() });
            Ok(json!({
                "sas": sas,
                "note": "Compare this SAS on BOTH screens — they MUST match. It is derived \
                         from the ML-KEM‖X25519 shared secret (the real MITM tripwire), not \
                         from public anchors. Confirm only if the phone shows the SAME digits.",
            }))
        }
        Some(other @ Pending::Confirming { .. }) => {
            // Already responded; keep it and reject the duplicate.
            inner.pending = Some(other);
            Err("already awaiting SAS confirmation — call pair_confirm or pair_cancel".into())
        }
        None => Err("no pairing in progress — start with pair_begin".into()),
    }
}

/// Confirm pairing — the **fail-closed** human gate (mirrors
/// [`SasConfirm::confirm_sas`]). `user_confirmed` MUST be the result of an explicit
/// "the codes match" action. If it is `false`, the ceremony is aborted and
/// **NOTHING is produced**: no [`PairingRecord`], no channel, no entry in the
/// paired list. Only on an affirmative confirmation is the record + live paired
/// channel persisted. (Fixes F-2 in code, not merely in UI copy.)
#[tauri::command]
pub fn pair_confirm(state: tauri::State<PairState>, user_confirmed: bool) -> Result<Value, String> {
    let mut inner = state.0.lock().unwrap();
    let (confirm, sas) = match inner.pending.take() {
        Some(Pending::Confirming { confirm, sas }) => (confirm, sas),
        Some(other) => {
            inner.pending = Some(other);
            return Err("no SAS to confirm yet — call pair_respond with the phone's PairingInit".into());
        }
        None => return Err("no pairing in progress — start with pair_begin".into()),
    };

    // The crate's fail-closed gate: `confirm_sas(false)` returns SasNotConfirmed and
    // yields no record/channel. We already `take()`- d `pending`, so a refusal leaves
    // NOTHING behind — the ceremony is fully aborted.
    let (record, channel) = confirm.confirm_sas(user_confirmed).map_err(|e| e.to_string())?;
    let nickname = record.nickname.clone();

    let id = inner.next_id();
    let requester = DesktopRequester::new(protocol_session_id(&channel));
    let peer_fingerprint = short_fingerprint(&record.peer_identity_pub);
    let binding_fingerprint = short_fingerprint(&record.channel_binding);
    inner.pairings.push(PairedDevice {
        id,
        nickname: nickname.clone(),
        record,
        channel,
        requester,
        sas: sas.clone(),
        paired_at: now_unix(),
        rev: Revocation::new(),
    });

    Ok(json!({
        "id": id,
        "nickname": nickname,
        "sas": sas,
        "peerFingerprint": peer_fingerprint,
        "channelBinding": binding_fingerprint,
        "note": "Paired. The SAS was confirmed, so a TOFU record + a live forward-secret, \
                 replay-guarded channel are pinned. Refusing the SAS persists nothing.",
    }))
}

/// The 16-byte protocol session id the [`DesktopRequester`] binds requests to,
/// derived from the paired channel's 32-byte session id (first 16 bytes) — the
/// same reduction [`postern_mobile_signer::PairedSignerChannel`] uses, so the
/// phone agrees.
fn protocol_session_id(channel: &PairingChannel) -> postern_signer_protocol::SessionId {
    let full = channel.session_id();
    let mut id = [0u8; 16];
    id.copy_from_slice(&full[..16]);
    id
}

/// Discard any in-progress pairing (drops + zeroizes the ephemeral secret / any
/// derived session key held in the pending state).
#[tauri::command]
pub fn pair_cancel(state: tauri::State<PairState>) -> Value {
    let mut inner = state.0.lock().unwrap();
    inner.pending = None;
    json!({ "ok": true })
}

/// The live paired-devices list: pinned peers with their SAS + TOFU fingerprint.
#[tauri::command]
pub fn pair_list(state: tauri::State<PairState>) -> Value {
    let inner = state.0.lock().unwrap();
    let items: Vec<Value> = inner
        .pairings
        .iter()
        .map(|p| {
            json!({
                "id": p.id,
                "nickname": p.nickname,
                "peerFingerprint": short_fingerprint(&p.record.peer_identity_pub),
                "channelBinding": short_fingerprint(&p.record.channel_binding),
                "sas": p.sas,
                "pairedAt": p.paired_at,
                "revoked": p.rev.is_revoked() || p.record.is_revoked(),
            })
        })
        .collect();
    json!({ "pairings": items })
}

/// Unpair / revoke a paired device: drop the pin (the crate's monotonic
/// [`PairingRecord::revoke`] wipes the session root + peer key) and revoke every
/// grant scoped to it. The org layer lifts off cleanly.
#[tauri::command]
pub fn pair_unpair(state: tauri::State<PairState>, id: u64) -> Result<Value, String> {
    let mut inner = state.0.lock().unwrap();
    let subject = {
        let p = inner
            .pairings
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or_else(|| format!("no pairing #{id}"))?;
        p.rev.revoke();
        p.record.revoke(); // wipes session_root + peer_identity_pub (forward secrecy)
        p.nickname.clone()
    };
    for g in inner.grants.iter_mut().filter(|g| g.subject == subject) {
        g.rev.revoke();
    }
    Ok(json!({ "ok": true, "revokedDevice": subject }))
}

// ───────────────────────────────────────────────────────────────────────────
// Commands — the wallet-LOGIN sign flow.
// ───────────────────────────────────────────────────────────────────────────

/// Compose a wallet-**LOGIN** sign-request for a paired phone and produce the
/// sealed wire frame to deliver over the LAN leg. The desktop holds no key: it
/// builds a [`LoginChallenge`] (the `consiglio:wallet-login:v1` shape) and drives
/// [`DesktopRequester::request_login`] — the request carries a fresh nonce,
/// a monotonic per-session counter, and the session binding. The resulting
/// protocol frame is then **sealed** under the paired channel (AEAD + per-direction
/// + monotonic counter + session id), so `key never on the wire` holds and the
/// phone opens it with its half of the same session.
#[tauri::command]
pub fn login_request(
    state: tauri::State<PairState>,
    org: String,
    user: String,
    session_id: u64,
) -> Result<Value, String> {
    let mut inner = state.0.lock().unwrap();
    login_request_inner(&mut inner, org, user, session_id)
}

/// Testable core of [`login_request`] — operates on the already-locked
/// [`PairInner`] so unit tests can drive the real requester/channel without Tauri.
fn login_request_inner(
    inner: &mut PairInner,
    org: String,
    user: String,
    session_id: u64,
) -> Result<Value, String> {
    let org = org.trim().to_string();
    let user = user.trim().to_string();
    if org.is_empty() || user.is_empty() {
        return Err("org and user are required for a wallet-login".into());
    }

    let device = inner
        .pairings
        .iter_mut()
        .find(|p| p.id == session_id && !p.rev.is_revoked() && !p.record.is_revoked())
        .ok_or_else(|| "no live paired device for this session — pair a phone first".to_string())?;

    // The exact bytes the phone will sign — byte-identical to a consiglio-auth
    // login transcript (domain `consiglio:wallet-login:v1`).
    let challenge = LoginChallenge {
        org: org.clone(),
        user: user.clone(),
        nonce: fresh_nonce(),
        issued_at: now_unix(),
    };

    // Compose + send via the SHIPPED requester over an in-memory capture channel,
    // then seal the captured protocol frame under the REAL paired channel.
    let mut cap = CaptureChannel::default();
    let sent = device
        .requester
        .request_login(&mut cap, &challenge)
        .map_err(|e| format!("compose sign-request: {e}"))?;
    let protocol_frame = cap
        .outbox
        .take()
        .ok_or_else(|| "requester produced no request frame".to_string())?;
    let sealed = device
        .channel
        .seal_frame(&protocol_frame)
        .map_err(|e| format!("seal request over paired channel: {e}"))?;
    let wire = sealed.to_bytes();

    // Copy the request coordinates OUT before `sent` is moved into the stored
    // SignReq — the login card surfaces the monotonic counter + fresh req-nonce
    // (WYSIWYS provenance) the phone will also see. All three are `Copy`.
    let transcript = sent.expected_digest;
    let counter = sent.counter;
    let req_nonce = sent.req_nonce;
    let id = inner.next_id();
    inner.requests.push(SignReq {
        id,
        pairing_id: session_id,
        org: org.clone(),
        user: user.clone(),
        challenge,
        sent,
        created: now_unix(),
        status: "pending",
    });

    Ok(json!({
        "id": id,
        "org": org,
        "user": user,
        "counter": counter,
        "reqNonce": hex::encode(req_nonce),
        "domain": String::from_utf8_lossy(LOGIN_DOMAIN),
        "transcript": hex::encode(transcript),
        // The sealed frame to hand to the LAN transport; the phone opens it with the
        // paired session key (the wallet key never travels — only this login request).
        "requestFrame": hex::encode(wire),
        "summary": format!("Log in to “{org}” as “{user}” — this signature can only be a login, \
                            never a payment (domain-separated transcript)."),
        "note": "Desktop holds NO key. It composed + sealed the request via the two shipped \
                 crates; the phone parses THESE bytes and shows what it is signing (WYSIWYS).",
    }))
}

/// Record the phone's approval and mint the scoped, expiring, revocable grant —
/// but **only after cryptographically verifying the phone's signature** over the
/// login transcript (fixes F-3). `approval_frame_hex` is the sealed `Approval`
/// frame the phone returned over the LAN leg. We open it with the paired channel,
/// match it to the request via [`DesktopRequester::recv_approval`], then run the
/// **hybrid Falcon‖ML-DSA verifier** (`bloch_crypto::crypto::verify`) over the
/// exact digest the desktop composed. A signature that does not verify mints
/// **no grant** (fail closed). `minutes` is the grant TTL.
#[tauri::command]
pub fn login_complete(
    state: tauri::State<PairState>,
    id: u64,
    approval_frame_hex: String,
    minutes: i64,
) -> Result<Value, String> {
    let mut inner = state.0.lock().unwrap();
    login_complete_inner(&mut inner, id, approval_frame_hex, minutes)
}

/// Testable core of [`login_complete`] — operates on the already-locked
/// [`PairInner`] so unit tests can exercise the fail-closed verification gates
/// (F-3 signature verify, F-A TOFU peer-pin, F-B revocation) without Tauri.
fn login_complete_inner(
    inner: &mut PairInner,
    id: u64,
    approval_frame_hex: String,
    minutes: i64,
) -> Result<Value, String> {
    let minutes = minutes.clamp(1, 24 * 60); // no blanket "approve all" (§3.4)
    let sealed_bytes = hex::decode(approval_frame_hex.trim())
        .map_err(|_| "approval frame is not valid hex".to_string())?;

    // Locate the request and its paired device.
    let (pairing_id, org, user, sent) = {
        let req = inner
            .requests
            .iter()
            .find(|r| r.id == id)
            .ok_or_else(|| format!("no sign-request #{id}"))?;
        if req.status == "approved" {
            return Err("this request is already completed".into());
        }
        if req.status == "rejected" {
            return Err("this request was rejected".into());
        }
        (req.pairing_id, req.org.clone(), req.user.clone(), req.sent.clone())
    };

    // ── F-B: fail-closed REVOCATION guard — the SAME guard `login_request` enforces,
    // now applied at completion. An in-flight request must NOT be allowed to complete
    // after the device was unpaired/revoked; a revoked record mints NO grant. This is
    // checked BEFORE opening the frame or minting anything (fail closed).
    {
        let device = inner
            .pairings
            .iter()
            .find(|p| p.id == pairing_id)
            .ok_or_else(|| "paired device for this request is gone (unpaired?)".to_string())?;
        if device.rev.is_revoked() || device.record.is_revoked() {
            return Err(
                "paired device was revoked/unpaired — refusing to complete an in-flight login (fail closed)"
                    .into(),
            );
        }
    }

    // Open (unseal + replay-check) the approval frame with the paired channel, then
    // match it to the request via the shipped requester.
    let approval = {
        let device = inner
            .pairings
            .iter_mut()
            .find(|p| p.id == pairing_id)
            .ok_or_else(|| "paired device for this request is gone (unpaired?)".to_string())?;
        let frame =
            Frame::from_bytes(&sealed_bytes).map_err(|e| format!("parse approval frame: {e}"))?;
        let opened = device
            .channel
            .open_frame(&frame)
            .map_err(|e| format!("open approval over paired channel (AEAD/replay): {e}"))?;
        let mut cap = CaptureChannel::with_inbox(opened.to_vec());
        device
            .requester
            .recv_approval(&mut cap, &sent)
            .map_err(|e| format!("approval does not match the request: {e}"))?
    };

    // ── F-3: VERIFY the phone's hybrid signature over the login transcript BEFORE
    // minting anything. The digest is the one the desktop composed (== the consiglio
    // transcript). We run the SAME verifier the node / consiglio server runs.
    //
    // HONEST CAVEAT: this proves the returned public key signed THIS login
    // transcript. Binding that public key to the *enrolled* identity for (org, user)
    // is the consiglio server's job (the relying party); the desktop terminal proves
    // the signature is real and refuses to mint a local grant otherwise.
    if approval.payload_digest != sent.expected_digest {
        return Err("approval digest does not match the composed transcript — refusing (fail closed)".into());
    }
    let sig_ok = bloch_crypto::crypto::verify(
        &approval.public_key,
        &sent.expected_digest,
        &approval.signature,
    );
    if !sig_ok {
        return Err(
            "phone signature did NOT verify over the login transcript — no grant minted (fail closed)"
                .into(),
        );
    }

    // ── F-A: TOFU peer-pin binding. A valid signature is necessary but NOT
    // sufficient — the signing key MUST be the peer we pinned at pairing. A valid
    // signature from a DIFFERENT key (key substitution / a second paired-looking
    // device) proves someone controls *some* key, not the key we trust for this
    // pairing. Bind the verified `approval.public_key` to the record's TOFU pin and
    // mint NO grant on a mismatch (fail closed). `peer_matches` is itself
    // revocation-aware, so a revoked record also fails here.
    let peer_pinned = inner
        .pairings
        .iter()
        .find(|p| p.id == pairing_id)
        .map(|p| p.record.peer_matches(&approval.public_key))
        .unwrap_or(false);
    if !peer_pinned {
        return Err(
            "phone signing key does NOT match the TOFU-pinned peer for this pairing — no grant minted (fail closed)"
                .into(),
        );
    }

    // Mark the request approved now that the signature is proven.
    if let Some(req) = inner.requests.iter_mut().find(|r| r.id == id) {
        req.status = "approved";
    }

    let subject = inner
        .pairings
        .iter()
        .find(|p| p.id == pairing_id)
        .map(|p| p.nickname.clone())
        .unwrap_or_else(|| "phone".to_string());

    let expiry_dt = OffsetDateTime::now_utc() + Duration::minutes(minutes);
    let expiry_raw = expiry_dt
        .format(&Rfc3339)
        .map_err(|e| format!("cannot format grant expiry: {e}"))?;
    // Sanity: parse + require future under the SAME kernel the list uses.
    Expiry::checked(&expiry_raw, OffsetDateTime::now_utc()).map_err(|e| e.to_string())?;

    let gid = inner.next_id();
    inner.grants.push(Grant {
        id: gid,
        scope: format!("wallet-login:{org}"),
        subject: subject.clone(),
        org: org.clone(),
        expiry_raw: expiry_raw.clone(),
        created: now_unix(),
        rev: Revocation::new(),
    });

    Ok(json!({
        "grantId": gid,
        "scope": format!("wallet-login:{org}"),
        "subject": subject,
        "user": user,
        "expiry": expiry_raw,
        "signatureVerified": true,
        "note": "Phone signature VERIFIED over the login transcript (hybrid Falcon‖ML-DSA). \
                 Minted a time-boxed, revocable grant — visible in Grants with a revoke button. \
                 Silence defaults to deny.",
    }))
}

/// Reject/cancel an outstanding login sign-request.
#[tauri::command]
pub fn login_reject(state: tauri::State<PairState>, id: u64) -> Result<Value, String> {
    let mut inner = state.0.lock().unwrap();
    let req = inner
        .requests
        .iter_mut()
        .find(|r| r.id == id)
        .ok_or_else(|| format!("no sign-request #{id}"))?;
    req.status = "rejected";
    Ok(json!({ "ok": true }))
}

/// The live grants list: each grant re-evaluated **fail-closed at this boundary**
/// through the shared `postern-policy` kernel — revoked or expired both collapse to
/// "never given". Includes the honest, typed enforcement caveat.
#[tauri::command]
pub fn grants_list(state: tauri::State<PairState>) -> Value {
    let inner = state.0.lock().unwrap();
    let now = OffsetDateTime::now_utc();
    let items: Vec<Value> = inner
        .grants
        .iter()
        .map(|g| {
            let (decision, remaining) = match Expiry::parse(&g.expiry_raw) {
                Ok(e) => {
                    let dec = g.rev.gate(&e, now);
                    let rem = (e.instant() - now).whole_seconds().max(0);
                    (dec, rem)
                }
                Err(err) => (Decision::deny(err.to_string()), 0),
            };
            json!({
                "id": g.id,
                "scope": g.scope,
                "subject": g.subject,
                "org": g.org,
                "expiry": g.expiry_raw,
                "createdAt": g.created,
                "remainingSecs": remaining,
                "revoked": g.rev.is_revoked(),
                "allow": decision.is_allow(),
                "reason": decision.reason(),
            })
        })
        .collect();
    json!({
        "grants": items,
        "enforcement": EnforcementMode::ByConstruction.honest_label(),
    })
}

/// Revoke a grant (monotonic; treated as never given at the next boundary).
#[tauri::command]
pub fn grant_revoke(state: tauri::State<PairState>, id: u64) -> Result<Value, String> {
    let mut inner = state.0.lock().unwrap();
    let g = inner
        .grants
        .iter_mut()
        .find(|g| g.id == id)
        .ok_or_else(|| format!("no grant #{id}"))?;
    g.rev.revoke();
    Ok(json!({ "ok": true }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use postern_pairing::{Channel as PairChannel, PairingError, QrPayload};
    use postern_signer_protocol::{PhoneApprover, SignerError, WalletSigner};

    /// A REAL hybrid Falcon‖ML-DSA signer (bloch-crypto) for the phone side of the
    /// end-to-end tests — unlike the crate's SHA3 `ScaffoldSigner`, this produces
    /// signatures that the desktop's `bloch_crypto::crypto::verify` actually accepts,
    /// so we can exercise the F-A/F-B gates AFTER a genuine signature verifies.
    struct RealWallet {
        pk: Vec<u8>,
        sk: Vec<u8>,
    }

    impl RealWallet {
        fn from_seed(seed: &[u8; 32]) -> Self {
            let (pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(seed).unwrap();
            RealWallet { pk, sk }
        }
    }

    impl WalletSigner for RealWallet {
        fn public_key_hex(&self) -> String {
            hex::encode(&self.pk)
        }
        fn public_key_bytes(&self) -> Vec<u8> {
            self.pk.clone()
        }
        fn address(&self) -> String {
            format!("bloch1test{}", short_fingerprint(&self.pk))
        }
        fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, SignerError> {
            Ok(bloch_crypto::crypto::sign(&self.sk, digest).unwrap())
        }
    }

    /// Drive the full pairing ceremony (both sides) and seed a live `PairInner`
    /// holding one paired device. `pinned_peer_pub` is the phone's identity key the
    /// desktop TOFU-pins (== the phone's wallet pubkey in the honest case). Returns
    /// the seeded state, the pairing id, and the PHONE's live channel end.
    fn paired_state(pinned_peer_pub: Vec<u8>) -> (PairInner, u64, PairChannel) {
        let (pending, qr) =
            Pairing::begin_desktop("phone", "lan:1", DESKTOP_KEYLESS_IDENTITY.to_vec());
        let qr = QrPayload::from_bytes(&qr.to_bytes()).unwrap();
        let (phone_confirm, init) =
            Pairing::scan_desktop_qr(&qr, "phone", pinned_peer_pub).unwrap();
        let init = PairingInit::from_bytes(&init.to_bytes()).unwrap();
        let desk_confirm = pending.accept(&init).unwrap();
        assert_eq!(phone_confirm.sas().digits(), desk_confirm.sas().digits());
        let sas = desk_confirm.sas().digits();

        let (record, channel) = desk_confirm.confirm_sas(true).unwrap();
        let (_phone_record, phone_channel) = phone_confirm.confirm_sas(true).unwrap();

        let mut inner = PairInner::default();
        let id = inner.next_id();
        let requester = DesktopRequester::new(protocol_session_id(&channel));
        inner.pairings.push(PairedDevice {
            id,
            nickname: "phone".into(),
            record,
            channel,
            requester,
            sas,
            paired_at: now_unix(),
            rev: Revocation::new(),
        });
        (inner, id, phone_channel)
    }

    /// The phone opens the desktop's sealed request, approves + signs it with
    /// `signer`, and returns the hex of the sealed `Approval` frame to hand back.
    fn phone_sign_approval<S: WalletSigner>(
        phone_channel: &mut PairChannel,
        request_frame_hex: &str,
        signer: S,
    ) -> String {
        let wire = hex::decode(request_frame_hex).unwrap();
        let req_frame = Frame::from_bytes(&wire).unwrap();
        let opened = phone_channel.open_frame(&req_frame).unwrap();
        let session_id = protocol_session_id(phone_channel);

        let mut approver = PhoneApprover::new(signer, session_id, "desktop");
        let mut cap = CaptureChannel::with_inbox(opened.to_vec());
        let pending = approver.receive(&mut cap).unwrap();
        approver.approve(&mut cap, pending).unwrap();
        let proto = cap.outbox.take().unwrap();
        let sealed = phone_channel.seal_frame(&proto).unwrap();
        hex::encode(sealed.to_bytes())
    }

    /// Happy path: a genuine signature from the TOFU-pinned peer mints the grant.
    /// (Anchors the harness so the F-A/F-B negatives are meaningful.)
    #[test]
    fn pinned_peer_valid_signature_mints_grant() {
        let wallet = RealWallet::from_seed(&[7u8; 32]);
        let (mut inner, id, mut phone) = paired_state(wallet.public_key_bytes());

        let req = login_request_inner(&mut inner, "acme".into(), "alice".into(), id).unwrap();
        let req_id = req["id"].as_u64().unwrap();
        let frame_hex = req["requestFrame"].as_str().unwrap().to_string();

        let approval_hex = phone_sign_approval(&mut phone, &frame_hex, wallet);
        let out = login_complete_inner(&mut inner, req_id, approval_hex, 30).unwrap();
        assert_eq!(out["signatureVerified"], json!(true));
        assert_eq!(inner.grants.len(), 1);
    }

    /// F-A: a VALID signature from a DIFFERENT (unpinned) key is rejected. The
    /// signature verifies cryptographically, but the key is not the TOFU-pinned
    /// peer — so NO grant is minted (fail closed).
    #[test]
    fn valid_signature_from_unpinned_key_is_rejected() {
        let honest = RealWallet::from_seed(&[7u8; 32]);
        let pinned = honest.public_key_bytes();
        let (mut inner, id, mut phone) = paired_state(pinned.clone());

        let req = login_request_inner(&mut inner, "acme".into(), "alice".into(), id).unwrap();
        let req_id = req["id"].as_u64().unwrap();
        let frame_hex = req["requestFrame"].as_str().unwrap().to_string();

        // A DIFFERENT valid keypair signs the SAME transcript.
        let attacker = RealWallet::from_seed(&[42u8; 32]);
        assert_ne!(attacker.public_key_bytes(), pinned);

        let approval_hex = phone_sign_approval(&mut phone, &frame_hex, attacker);
        let err = login_complete_inner(&mut inner, req_id, approval_hex, 30).unwrap_err();
        assert!(
            err.contains("TOFU-pinned peer"),
            "expected a peer-pin rejection, got: {err}"
        );
        assert!(inner.grants.is_empty(), "a mismatched-peer key must mint NO grant");
    }

    /// F-B: an in-flight request cannot complete after the device is unpaired. Even
    /// with a valid, correctly-pinned signature in hand, revoking the pairing before
    /// completion mints NO grant (fail closed).
    #[test]
    fn revoked_device_cannot_complete_inflight_login() {
        let wallet = RealWallet::from_seed(&[7u8; 32]);
        let (mut inner, id, mut phone) = paired_state(wallet.public_key_bytes());

        let req = login_request_inner(&mut inner, "acme".into(), "alice".into(), id).unwrap();
        let req_id = req["id"].as_u64().unwrap();
        let frame_hex = req["requestFrame"].as_str().unwrap().to_string();

        // The phone signs a perfectly valid approval while paired…
        let approval_hex = phone_sign_approval(&mut phone, &frame_hex, wallet);

        // …but the human unpairs/revokes BEFORE the approval is completed.
        for p in inner.pairings.iter_mut().filter(|p| p.id == id) {
            p.rev.revoke();
            p.record.revoke();
        }

        let err = login_complete_inner(&mut inner, req_id, approval_hex, 30).unwrap_err();
        assert!(
            err.contains("revoked") || err.contains("unpaired"),
            "expected a revocation rejection, got: {err}"
        );
        assert!(inner.grants.is_empty(), "a revoked device must mint NO grant");
    }

    /// Drive the crate ceremony end-to-end WITHOUT Tauri to prove the invariants
    /// the commands rely on: the KEM-bound SAS agrees, and the fail-closed gate
    /// (F-2) yields NOTHING on a refusal.
    #[test]
    fn kem_sas_agrees_and_refusal_persists_nothing() {
        let (pending, qr) =
            Pairing::begin_desktop("phone", "lan:1", DESKTOP_KEYLESS_IDENTITY.to_vec());
        let qr = QrPayload::from_bytes(&qr.to_bytes()).unwrap();
        let (phone_confirm, init) =
            Pairing::scan_desktop_qr(&qr, "Tiago's ThinkPad", vec![0xBE, 0xEF]).unwrap();
        let init = PairingInit::from_bytes(&init.to_bytes()).unwrap();
        let desk_confirm = pending.accept(&init).unwrap();

        // Same KEM shared secret → same SAS on both screens (no MITM).
        assert_eq!(phone_confirm.sas().digits(), desk_confirm.sas().digits());

        // F-2: refusing the SAS produces no record/channel.
        assert_eq!(
            desk_confirm.confirm_sas(false).unwrap_err(),
            PairingError::SasNotConfirmed
        );
    }

    /// The desktop composes a `SignRequest` whose signed digest equals the
    /// `LoginChallenge` transcript — the exact bytes the phone signs.
    #[test]
    fn composed_request_digest_matches_login_transcript() {
        // A throwaway session id; the digest is independent of it.
        let mut requester = DesktopRequester::new([9u8; 16]);
        let challenge = LoginChallenge {
            org: "acme".into(),
            user: "alice".into(),
            nonce: [3u8; 32],
            issued_at: 1_000,
        };
        let mut cap = CaptureChannel::default();
        let sent = requester.request_login(&mut cap, &challenge).unwrap();
        assert_eq!(sent.expected_digest, challenge.signing_digest());
        // The captured frame really is a signer-protocol frame of the request.
        assert!(cap.outbox.is_some());
    }
}
