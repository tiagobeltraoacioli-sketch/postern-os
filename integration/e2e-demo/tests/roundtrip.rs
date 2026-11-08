// SPDX-License-Identifier: MIT OR Apache-2.0
//! CI-checkable version of the demo's guarantee: the whole pairing →
//! login-request → WYSIWYS approve+sign → REAL hybrid-verify round-trip, over the
//! in-process loopback, asserting the honest invariants at each seam.
//!
//! SCAFFOLD/UNAUDITED — nothing here is deployed. The private key never crosses
//! the wire; only a signature comes back.

use bloch_crypto::crypto::verify as hybrid_verify;

use postern_pairing::transport::{LoopbackPair, Transport};
use postern_pairing::{Pairing, PairingInit, QrPayload};

use postern_signer_protocol::channel::Channel as ProtocolChannel;
use postern_signer_protocol::{DesktopRequester, LoginChallenge};

use postern_mobile_signer::{
    MobileSigner, PairedSignerChannel, PresenceMethod, PresenceProof, Tier, WalletCoreSigner,
};

fn login() -> LoginChallenge {
    LoginChallenge {
        org: "acme-corp".into(),
        user: "alice".into(),
        nonce: [0x11u8; 32],
        issued_at: 1_752_000_000,
    }
}

#[test]
fn full_pairing_then_login_sign_verifies_and_replay_is_refused() {
    // ── Pairing ceremony (Dev1) over a loopback transport ────────────────────
    let (desk_pending, qr) =
        Pairing::begin_desktop("Tiago's ThinkPad", "192.168.1.20:47001", b"desktop-id".to_vec());
    let scanned = QrPayload::from_bytes(&qr.to_bytes()).unwrap();
    let (phone_confirm, init) =
        Pairing::scan_desktop_qr(&scanned, "Tiago's Pixel", b"phone-id".to_vec()).unwrap();

    let (mut phone_link, mut desk_link) = LoopbackPair::new();
    phone_link.send(&init.to_bytes()).unwrap();
    let init_parsed = PairingInit::from_bytes(&desk_link.recv().unwrap()).unwrap();
    let desk_confirm = desk_pending.accept(&init_parsed).unwrap();

    // No MITM in the loopback → the SAS matches; the human confirms → channels open.
    assert!(phone_confirm.sas().matches(desk_confirm.sas()));
    assert_eq!(phone_confirm.sas().digits(), desk_confirm.sas().digits());
    let (_phone_rec, phone_secure) = phone_confirm.confirm_sas(true).unwrap();
    let (_desk_rec, desk_secure) = desk_confirm.confirm_sas(true).unwrap();

    // ── Bridge into the signer protocol (Dev3) ───────────────────────────────
    let mut desk_chan = PairedSignerChannel::new(desk_secure, desk_link);
    let mut phone_chan = PairedSignerChannel::new(phone_secure, phone_link);
    let session_id = desk_chan.protocol_session_id();
    assert_eq!(session_id, phone_chan.protocol_session_id());

    let wallet = WalletCoreSigner::from_seed_bytes(&[9u8; 32], true).unwrap();
    let mut phone = MobileSigner::new(wallet, session_id, "Tiago's ThinkPad");
    let mut desktop = DesktopRequester::new(session_id);

    // ── Login request → WYSIWYS → per-sign presence → approve+sign (Dev2) ─────
    let challenge = login();
    let sent = desktop.request_login(&mut desk_chan, &challenge).unwrap();

    let request_frame = phone_chan.recv().unwrap();
    let prompt = phone.receive_frame(&request_frame).unwrap();
    assert_eq!(prompt.tier, Tier::SingleTap);
    assert!(!prompt.can_move_funds); // a login can never move funds
    assert_eq!(prompt.peer_device, "Tiago's ThinkPad");

    let mut req_nonce = [0u8; 32];
    req_nonce.copy_from_slice(&hex::decode(&prompt.req_nonce_hex).unwrap());
    let approval_frame = phone
        .approve(PresenceProof::granted(req_nonce, PresenceMethod::Biometric))
        .unwrap();
    phone_chan.send(&approval_frame).unwrap();

    let approval = desktop.recv_approval(&mut desk_chan, &sent).unwrap();

    // ── The signature verifies with the REAL hybrid verifier ─────────────────
    assert_eq!(approval.payload_digest, challenge.signing_digest());
    assert!(hybrid_verify(
        &approval.public_key,
        &challenge.signing_digest(),
        &approval.signature
    ));

    // The approval frame must never carry the wallet seed (structural rail).
    assert!(!approval_frame.windows(32).any(|w| w == [9u8; 32]));

    // ── Replay is refused (fail-closed) ──────────────────────────────────────
    assert!(phone.receive_frame(&request_frame).is_err());
}

#[test]
fn refusing_the_sas_produces_no_channel() {
    let (desk_pending, qr) = Pairing::begin_desktop("d", "l", b"desk".to_vec());
    let (phone_confirm, init) = Pairing::scan_desktop_qr(&qr, "p", b"phone".to_vec()).unwrap();
    let desk_confirm = desk_pending.accept(&init).unwrap();
    // The human says the codes do not match → fail-closed on both sides.
    assert!(phone_confirm.confirm_sas(false).is_err());
    assert!(desk_confirm.confirm_sas(false).is_err());
}
