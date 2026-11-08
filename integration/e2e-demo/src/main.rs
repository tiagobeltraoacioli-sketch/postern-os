// SPDX-License-Identifier: MIT OR Apache-2.0
//! # phone-signer-e2e — the whole mobile<->desktop flow, end to end, printed
//!
//! ## SCAFFOLD — not a secure, audited, or deployed system
//!
//! This binary is the honest "the pieces fit" walkthrough for anyone building a
//! conformant end (a real mobile app, a real desktop terminal). It wires the
//! THREE shipped crates through their **public APIs only** and drives one full
//! round-trip over an in-process loopback transport (no sockets, no network):
//!
//! ```text
//!  Desktop (terminal, holds NOTHING)                Phone (custodian, holds the key)
//!  ─────────────────────────────────                ────────────────────────────────
//!  1. begin_desktop() ── QR (anchor) ──────────────▶ 2. scan_desktop_qr(): pin anchor,
//!       ephemeral ML-KEM‖X25519 keypair                  encapsulate → session key,
//!            ◀──────── PairingInit (kem_ct) ─────────     derive 6-digit SAS
//!  3. accept(): decapsulate → SAME session key
//!  4. [both compare the 6-digit SAS on screen]      4. [both compare the SAS on screen]
//!  5. confirm_sas(true) → (Record, Channel)         5. confirm_sas(true) → (Record, Channel)
//!  ── now a PQ-hybrid, replay-guarded channel ──
//!  6. request_login(challenge) ────────────────────▶ 7. receive_frame(): replay guard,
//!       (over the sealed paired channel)                 decode payload, render WYSIWYS
//!                                                       8. per-sign presence → sign digest
//!  9. recv_approval() ◀──── Approval (sig,pk) ──────    (key NEVER crosses the wire)
//! 10. verify() with the REAL hybrid Falcon‖ML-DSA verifier — the same one the node runs
//! ```
//!
//! Every honest step prints. Run: `cargo run` from this directory.
//!
//! ### Binding rails (do not let a UI round these off)
//! - **Scaffold, unaudited.** Nothing here is built on hardware, attested, or
//!   deployed. Internal review is not an audit.
//! - **The private key NEVER crosses the wire — structurally.** Only signatures
//!   and public keys travel back. This is enforced by the type system, not by
//!   this demo's good behavior.
//! - **Software signing in RAM is NOT a hardware wallet.** Even on the phone the
//!   PQ secret is in RAM at sign time. A rooted endpoint (A5) reads it and can
//!   forge the approval UI; nothing here fixes that.
//! - **QR + SAS are MANDATORY and fail-closed.** The human SAS comparison is the
//!   only thing that stops an active MITM. Refuse it and no channel is produced.
//! - **Local-first.** No cloud, no relay, no telemetry. The coin (BLCH) is not a
//!   security. Community edition is "Postern for postmarketOS — community
//!   edition", never "Postern OS"; the assurance name is never "BABA YAGA".

use bloch_crypto::crypto::verify as hybrid_verify;

use postern_pairing::transport::{LoopbackPair, Transport};
use postern_pairing::{Pairing, PairingInit, QrPayload};

use postern_signer_protocol::channel::Channel as ProtocolChannel;
use postern_signer_protocol::{DesktopRequester, LoginChallenge};

use postern_mobile_signer::{
    MobileSigner, PairedSignerChannel, PresenceMethod, PresenceProof, WalletCoreSigner,
};

/// Print a numbered ceremony step header.
fn step(n: u32, who: &str, what: &str) {
    println!("\n[{n:>2}] {who:<8} │ {what}");
}

/// Print an indented detail line under the current step.
fn detail(label: &str, value: &str) {
    println!("        {label:<20} {value}");
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!("║  Postern phone-as-signer — END-TO-END DEMO  (SCAFFOLD, UNAUDITED)       ║");
    println!("║  pairing (Dev1) + signer-protocol (Dev2) + mobile-signer (Dev3)        ║");
    println!("║  desktop-requests-login → phone-approves-and-signs → real verify       ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝");
    println!(
        "\nNOTE: everything runs in ONE process over an in-memory loopback — no\n\
         sockets, no network. The transport is an UNAUTHENTICATED bearer; all\n\
         security lives in the QR-pin + SAS + the PQ-hybrid channel on top of it."
    );

    // The two devices' long-term identity public keys. Opaque to the pairing
    // crate — it only pins and compares them (TOFU). A real app supplies whatever
    // identity key its device layer uses.
    let desktop_identity = b"desktop-identity-pub-key".to_vec();
    let phone_identity = b"phone-identity-pub-key".to_vec();

    // ── PART A — the pairing ceremony (Dev1) ──────────────────────────────────

    step(1, "Desktop", "begin_desktop(): fresh EPHEMERAL ML-KEM-1024‖X25519 anchor + nonce → QR");
    let (desk_pending, qr): (_, QrPayload) =
        Pairing::begin_desktop("Tiago's ThinkPad", "192.168.1.20:47001", desktop_identity);
    let qr_bytes = qr.to_bytes();
    let qr_hex = qr.to_hex();
    detail("anchor pubkey len", &format!("{} bytes (ML-KEM-1024 ek ‖ X25519 pk)", qr.anchor_public.len()));
    detail("QR payload", &format!("{} bytes; hex head: {}…", qr_bytes.len(), &qr_hex[..48]));
    detail("channel binding", &format!("SHA-256(nonce ‖ anchor) = {}…", hex::encode(&desk_pending.channel_binding()[..8])));

    step(2, "Phone", "scan_desktop_qr(): pin the anchor off the glass, encapsulate → session key, derive SAS");
    let scanned = QrPayload::from_bytes(&qr_bytes).expect("QR round-trips");
    let (phone_confirm, init) =
        Pairing::scan_desktop_qr(&scanned, "Tiago's Pixel", phone_identity).expect("scan ok");
    detail("phone SAS", phone_confirm.sas().digits().as_str());

    step(2, "Phone", "reply with PairingInit (hybrid kem_ct ‖ identity) over the UNTRUSTED transport");
    // A real LAN socket; here an in-process duplex. `phone_link`/`desk_link` are
    // the two crossed ends.
    let (mut phone_link, mut desk_link) = LoopbackPair::new();
    phone_link.send(&init.to_bytes()).expect("send init");
    let init_bytes = desk_link.recv().expect("recv init");
    let init_parsed = PairingInit::from_bytes(&init_bytes).expect("init round-trips");
    detail("kem_ct len", &format!("{} bytes (ML-KEM ct ‖ X25519 ephemeral pk)", init_parsed.kem_ct.len()));

    step(3, "Desktop", "accept(): decapsulate the kem_ct with the ephemeral secret → SAME session key → derive SAS");
    let desk_confirm = desk_pending.accept(&init_parsed).expect("accept ok");
    detail("desktop SAS", desk_confirm.sas().digits().as_str());

    step(4, "Human", "compare the two 6-digit SAS values across BOTH screens (the only anti-MITM tripwire)");
    let sas_match = phone_confirm.sas().matches(desk_confirm.sas());
    detail("phone shows", phone_confirm.sas().digits().as_str());
    detail("desktop shows", desk_confirm.sas().digits().as_str());
    detail("match?", if sas_match { "YES → the human confirms" } else { "NO → the human ABORTS (fail-closed)" });
    assert!(sas_match, "no MITM in the loopback → SAS must match");

    step(5, "Both", "confirm_sas(true): fail-closed gate → each side gets a PairingRecord + a live PQ-hybrid Channel");
    let (phone_rec, phone_secure) = phone_confirm.confirm_sas(true).expect("phone confirm");
    let (desk_rec, desk_secure) = desk_confirm.confirm_sas(true).expect("desk confirm");
    detail("phone role", &format!("{:?} (holds the wallet key)", phone_rec.role));
    detail("desktop role", &format!("{:?} (holds NOTHING)", desk_rec.role));
    detail("peer pins (TOFU)", &format!(
        "phone↔{} · desktop↔{}",
        if phone_rec.peer_matches(b"desktop-identity-pub-key") { "desktop OK" } else { "MISMATCH" },
        if desk_rec.peer_matches(b"phone-identity-pub-key") { "phone OK" } else { "MISMATCH" },
    ));

    // ── PART B — bridge the paired channel into the signer protocol (Dev3) ────

    step(6, "Both", "wrap each paired Channel + transport into a PairedSignerChannel (seal→transport→open)");
    // The bridge (Dev3) rides the request/approve protocol over the real paired,
    // AEAD-sealed, replay-guarded channel. The transport ends move in here.
    let mut desk_chan = PairedSignerChannel::new(desk_secure, desk_link);
    let mut phone_chan = PairedSignerChannel::new(phone_secure, phone_link);
    // Both ends derive the SAME 16-byte protocol session id from the paired
    // session — the replay/session-binding anchor for every request.
    let session_id = desk_chan.protocol_session_id();
    assert_eq!(session_id, phone_chan.protocol_session_id(), "both ends agree on the session id");
    detail("protocol session id", &hex::encode(session_id));

    // The phone builds its REAL wallet (hybrid Falcon‖ML-DSA via WalletCore). The
    // seed here is deterministic scaffold entropy — a real phone restores from a
    // BIP39 mnemonic behind the OS keystore.
    let wallet = WalletCoreSigner::from_seed_bytes(&[9u8; 32], /*testnet=*/ true)
        .expect("wallet builds");
    let mut phone = MobileSigner::new(wallet, session_id, "Tiago's ThinkPad");
    detail("phone wallet address", &phone.address());

    // The desktop is the requester; it holds no key and only a monotonic counter.
    let mut desktop = DesktopRequester::new(session_id);

    // ── PART C — the phone-as-signer round-trip (Dev2 protocol) ───────────────

    // The consiglio-shaped wallet-login challenge the desktop wants signed. Its
    // signing digest is byte-identical to `postern-consiglio-auth`'s transcript,
    // so a signature here logs the user in against the same enrolled key.
    let challenge = LoginChallenge {
        org: "acme-corp".into(),
        user: "alice".into(),
        nonce: [0x11u8; 32],
        issued_at: 1_752_000_000,
    };

    step(6, "Desktop", "request_login(): fresh nonce + monotonic counter + session binding, sealed over the channel");
    let sent = desktop.request_login(&mut desk_chan, &challenge).expect("send request");
    detail("expected digest", &hex::encode(sent.expected_digest));
    detail("counter", &sent.counter.to_string());

    step(7, "Phone", "receive the sealed frame off the channel, run the replay guard, decode the ACTUAL bytes, render WYSIWYS");
    // Pull the sealed frame off the paired channel → plaintext protocol frame.
    let request_frame = phone_chan.recv().expect("phone receives the sealed request");
    let prompt = phone.receive_frame(&request_frame).expect("valid request → WYSIWYS");
    detail("tier", &format!("{:?}", prompt.tier));
    detail("can move funds?", &prompt.can_move_funds.to_string());
    detail("peer device", &prompt.peer_device);
    detail("confirmation frag", &prompt.confirmation_fragment);
    println!("        WYSIWYS sentence  \"{}\"", prompt.sentence);
    println!("        disclosure        \"{}…\"", &prompt.disclosure[..60]);

    step(8, "Human", "the phone owner performs a biometric check → a PresenceProof bound to THIS request's nonce");
    let mut req_nonce = [0u8; 32];
    req_nonce.copy_from_slice(&hex::decode(&prompt.req_nonce_hex).expect("nonce hex"));
    let presence = PresenceProof::granted(req_nonce, PresenceMethod::Biometric);
    detail("presence method", &format!("{:?} (per-sign; no blanket auto-approve)", presence.method()));

    step(8, "Phone", "approve(): sign the CANONICAL digest with the hybrid key, seal the Approval back over the channel");
    let approval_frame = phone.approve(presence).expect("sign + approve");
    phone_chan.send(&approval_frame).expect("phone sends the sealed approval");
    detail("approval frame", &format!("{} sealed bytes on the wire", approval_frame.len()));

    step(9, "Desktop", "recv_approval(): open the frame, match it to the request that was sent (session/nonce/counter/digest)");
    let approval = desktop.recv_approval(&mut desk_chan, &sent).expect("matched approval");
    detail("signature len", &format!("{} bytes (hybrid Falcon‖ML-DSA — PUBLIC)", approval.signature.len()));
    detail("public key len", &format!("{} bytes (identity — PUBLIC)", approval.public_key.len()));
    detail("payload digest", &hex::encode(approval.payload_digest));

    step(10, "Verify", "check the signature with the REAL hybrid verifier — the exact crypto::verify the node / consiglio server runs");
    let ok = hybrid_verify(&approval.public_key, &challenge.signing_digest(), &approval.signature);
    detail("verify result", if ok { "VALID - the phone proved it holds the wallet key" } else { "INVALID" });
    assert!(ok, "the phone's hybrid signature must verify against the login digest");
    assert_eq!(approval.payload_digest, challenge.signing_digest(), "signed digest == the challenge the desktop sent");

    // ── PART D — an honest negative proof: replay is refused ───────────────────

    step(11, "Phone", "NEGATIVE PROOF: re-feed the identical request frame — the committed replay guard refuses it (fail-closed)");
    let replayed = phone.receive_frame(&request_frame);
    detail("replay rejected?", &format!("{} ({})", replayed.is_err(),
        replayed.err().map(|e| e.to_string()).unwrap_or_default()));
    assert!(matches!(phone.receive_frame(&request_frame), Err(_)), "a replayed request must fail closed");

    println!("\n╔══════════════════════════════════════════════════════════════════════╗");
    println!("║  DONE — pairing → login request → WYSIWYS approve+sign → verify ✔       ║");
    println!("║  The private key never crossed the wire. Only a signature came back.    ║");
    println!("║  SCAFFOLD/UNAUDITED · software-in-RAM, NOT a hardware wallet · local.    ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝");
}
