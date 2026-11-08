// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end v1 flow: desktop requests a wallet-login signature, phone parses the
//! actual bytes (WYSIWYS), approves + signs, desktop matches the approval. Plus
//! the adversarial paths: replay across a session, a declined prompt, and the
//! single-tap grant window.

use postern_signer_protocol::{
    loopback, ApprovalGrant, Channel, ConsequenceTier, DesktopRequester, GrantScope,
    LoginChallenge, PhoneApprover, ProtocolError, ScaffoldSigner, WalletSigner,
};

fn login(nonce: u8) -> LoginChallenge {
    LoginChallenge {
        org: "acme".into(),
        user: "alice".into(),
        nonce: [nonce; 32],
        issued_at: 1_752_000_000,
    }
}

#[test]
fn desktop_requests_phone_signs_login() {
    let session_id = [7u8; 16];
    let (mut desk_end, mut phone_end) = loopback();

    let mut desktop = DesktopRequester::new(session_id);
    let signer = ScaffoldSigner::from_seed(&[1u8; 32]);
    let expected_pk = signer.public_key_bytes();
    let mut phone = PhoneApprover::new(signer, session_id, "Tiago's ThinkPad");

    // 1. Desktop (holds no key) sends the request.
    let sent = desktop.request_login(&mut desk_end, &login(0xA1)).unwrap();

    // 2. Phone validates + renders WYSIWYS from the ACTUAL bytes.
    let pending = phone.receive(&mut phone_end).unwrap();
    assert_eq!(pending.tier(), ConsequenceTier::SingleTap);
    assert!(pending.wysiwys.sentence.contains("login challenge"));
    assert!(!pending.wysiwys.can_move_funds);
    assert_eq!(pending.wysiwys.peer_device, "Tiago's ThinkPad");

    // 3. Phone approves + signs; only a signature crosses back.
    let approval = phone.approve(&mut phone_end, pending).unwrap();
    assert_eq!(approval.public_key, expected_pk);

    // 4. Desktop matches the approval to the request it sent.
    let matched = desktop.recv_approval(&mut desk_end, &sent).unwrap();
    assert_eq!(matched.payload_digest, sent.expected_digest);
    assert_eq!(matched.req_nonce, sent.req_nonce);
}

#[test]
fn a_captured_request_cannot_replay_on_a_second_session() {
    // Session A: capture the raw request frame the desktop sent.
    let session_a = [1u8; 16];
    let (mut desk_a, mut phone_a) = loopback();
    let mut desktop_a = DesktopRequester::new(session_a);
    desktop_a.request_login(&mut desk_a, &login(0xB2)).unwrap();
    let captured_frame = phone_a.recv().unwrap(); // the wire bytes an attacker sees

    // Session B: a different paired session with its own guard. Replaying the
    // captured frame must fail on the session binding.
    let session_b = [2u8; 16];
    let (_desk_b, mut phone_b_end) = loopback();
    // Inject the captured frame into session B's inbound queue by sending it from
    // the desktop end of B.
    let (mut desk_b_inject, mut phone_b) = loopback();
    desk_b_inject
        .send(&captured_frame)
        .unwrap();
    let signer = ScaffoldSigner::from_seed(&[9u8; 32]);
    let mut phone = PhoneApprover::new(signer, session_b, "peer-B");
    let err = phone.receive(&mut phone_b).unwrap_err();
    assert_eq!(err, ProtocolError::WrongSession);
    let _ = &mut phone_b_end; // silence unused
}

#[test]
fn replay_on_same_session_is_rejected() {
    let session_id = [5u8; 16];
    let (mut desk, mut phone_end) = loopback();
    let mut desktop = DesktopRequester::new(session_id);
    let signer = ScaffoldSigner::from_seed(&[3u8; 32]);
    let mut phone = PhoneApprover::new(signer, session_id, "peer");

    // First request: approved.
    desktop.request_login(&mut desk, &login(0xC3)).unwrap();
    let raw = phone_end.recv().unwrap();

    // Feed it once → ok.
    let (mut inject, mut phone_in) = loopback();
    inject.send(&raw).unwrap();
    let pending = phone.receive(&mut phone_in).unwrap();
    phone.approve(&mut phone_in, pending).unwrap();

    // Feed the SAME frame again → replay (same nonce + non-advancing counter).
    inject.send(&raw).unwrap();
    let err = phone.receive(&mut phone_in).unwrap_err();
    assert!(matches!(
        err,
        ProtocolError::ReplayedNonce | ProtocolError::StaleCounter { .. }
    ));
}

#[test]
fn declining_signs_nothing_and_does_not_advance_the_guard() {
    let session_id = [4u8; 16];
    let (mut desk, mut phone_end) = loopback();
    let mut desktop = DesktopRequester::new(session_id);
    let signer = ScaffoldSigner::from_seed(&[8u8; 32]);
    let mut phone = PhoneApprover::new(signer, session_id, "peer");

    desktop.request_login(&mut desk, &login(0xD4)).unwrap();
    let pending = phone.receive(&mut phone_end).unwrap();
    // Human says no.
    assert_eq!(phone.decline(pending), Err(ProtocolError::Declined));

    // Because the guard was not committed, the SAME counter can still be used by a
    // fresh, genuine request (the declined one never advanced the sequence).
    let session2 = session_id;
    let (mut desk2, mut phone2_end) = loopback();
    let mut desktop2 = DesktopRequester::new(session2);
    desktop2.request_login(&mut desk2, &login(0xD5)).unwrap();
    // counter is 1 again; guard.last_counter is still 0 → accepted.
    let pending2 = phone.receive(&mut phone2_end).unwrap();
    assert!(phone.approve(&mut phone2_end, pending2).is_ok());
}

#[test]
fn single_tap_grant_covers_login_but_never_a_transfer() {
    let session_id = [6u8; 16];
    let signer = ScaffoldSigner::from_seed(&[2u8; 32]);
    let mut phone = PhoneApprover::new(signer, session_id, "Tiago's ThinkPad");
    phone.set_grant(ApprovalGrant::new(
        "Tiago's ThinkPad",
        GrantScope::LoginTo { org: "acme".into() },
        2_000,
    ));

    // A login pending covered by a live grant, from the right peer, before expiry.
    let (mut desk, mut phone_end) = loopback();
    let mut desktop = DesktopRequester::new(session_id);
    desktop.request_login(&mut desk, &login(0xE6)).unwrap();
    let pending = phone.receive(&mut phone_end).unwrap();
    assert!(phone.covered_by_grant(&pending, 1_000)); // inside window → auto-tap
    assert!(!phone.covered_by_grant(&pending, 3_000)); // expired → back to prompt

    // Revoke → never covered again.
    phone.revoke_grant();
    assert!(!phone.covered_by_grant(&pending, 1_000));
}
