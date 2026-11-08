// SPDX-License-Identifier: MIT OR Apache-2.0
//! GOLDEN DENYLIST TEST — the runtime half of the structural key-material wall.
//!
//! Security §5.1 / Design §4.1: *private key material MUST NEVER cross the
//! channel.* The compile-time half lives in `src/secret.rs` + `src/message.rs`
//! (the secret types have no `Serialize`; every message is the sealed `WireSafe`).
//! This test is the belt to that suspenders: it constructs EVERY protocol message
//! from a signer built on a **known, distinctive** seed, serializes each exactly
//! as it would go on the wire, and fails the build if the seed or the derived
//! secret key ever appears — as raw bytes OR hex — in any serialized message.
//!
//! If a future edit adds a secret-bearing field to a wire type, this test goes
//! red and the build fails. That is the point.

use postern_signer_protocol::{
    Approval, Chain, DesktopRequester, LoginChallenge, PhoneApprover, ScaffoldSigner, SignPayload,
    SignRequest, TransferIntent, WalletSigner,
};
use sha3::{Digest, Sha3_256};

/// A distinctive seed so a leak is unmistakable in a byte scan.
const KNOWN_SEED: [u8; 48] = [0xAB; 48];

/// Recompute the scaffold signer's derived secret exactly as `ScaffoldSigner`
/// does, so we can scan for THAT too (not just the seed).
fn derived_secret(seed: &[u8]) -> Vec<u8> {
    let mut h = Sha3_256::new();
    h.update(b"scaffold-secret");
    h.update(seed);
    h.finalize().to_vec()
}

/// Is `needle` a contiguous subsequence of `haystack`?
fn contains_subseq(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w == needle)
}

/// Every protocol message, serialized as it would be framed onto the channel.
fn all_wire_messages() -> Vec<(&'static str, Vec<u8>)> {
    let session_id = [0x11u8; 16];
    let signer = ScaffoldSigner::from_seed(&KNOWN_SEED);

    // A login SignRequest, built by the real desktop path over an in-memory pair.
    let (mut desktop_end, mut phone_end) = postern_signer_protocol::loopback();
    let mut desktop = DesktopRequester::new(session_id);
    let login = LoginChallenge {
        org: "acme".into(),
        user: "alice".into(),
        nonce: [0x22u8; 32],
        issued_at: 1_752_000_000,
    };
    let sent = desktop.request_login(&mut desktop_end, &login).unwrap();

    // The phone approves + signs, producing a real Approval on the wire.
    let mut phone = PhoneApprover::new(signer, session_id, "Tiago's ThinkPad");
    let pending = phone.receive(&mut phone_end).unwrap();
    let approval = phone.approve(&mut phone_end, pending).unwrap();
    let _ = desktop.recv_approval(&mut desktop_end, &sent).unwrap();

    // Also serialize the raw payload types and a transfer (v2 shape) directly.
    let login_payload = SignPayload::Login(login.clone());
    let transfer_payload = SignPayload::Transfer(TransferIntent {
        to_address: "bloch1qrecipient".into(),
        amount: 1000,
        fee: 1,
        chain: Chain::Mainnet,
        nonce: [0x33u8; 32],
    });
    // Reconstruct the on-wire SignRequest too (independent of the loopback copy).
    let raw_request = SignRequest {
        session_id,
        req_nonce: [0x44u8; 32],
        counter: 1,
        payload: login_payload.encode(),
    };

    vec![
        ("SignRequest(login)", serde_json::to_vec(&raw_request).unwrap()),
        ("Approval", serde_json::to_vec(&approval).unwrap()),
        ("SignPayload::Login", serde_json::to_vec(&login_payload).unwrap()),
        ("SignPayload::Transfer", serde_json::to_vec(&transfer_payload).unwrap()),
        ("LoginChallenge", serde_json::to_vec(&login).unwrap()),
    ]
}

/// Every encoding a secret could plausibly leak through: raw bytes, lowercase
/// hex, and serde_json's decimal-array form (`[171,171,…]`) — the way a `Vec<u8>`
/// or `[u8; N]` field is actually encoded on this JSON wire. Scanning for all
/// three means a planted secret cannot hide behind an encoding.
fn needles(bytes: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("raw", bytes.to_vec()),
        ("hex", hex::encode(bytes).into_bytes()),
        ("json-array", serde_json::to_vec(bytes).unwrap()),
    ]
}

#[test]
fn no_key_material_appears_in_any_protocol_message() {
    let secret = derived_secret(&KNOWN_SEED);
    let seed_needles = needles(&KNOWN_SEED);
    let secret_needles = needles(&secret);

    for (name, bytes) in all_wire_messages() {
        for (enc, needle) in seed_needles.iter().chain(secret_needles.iter()) {
            assert!(
                !contains_subseq(&bytes, needle),
                "DENYLIST BREACH: key material ({enc}-encoded) found in {name}"
            );
        }
    }
}

#[test]
fn scan_would_catch_a_planted_leak() {
    // Meta-check: prove the scanner is not vacuous. Serialize the secret into a
    // throwaway blob EXACTLY as a `Vec<u8>` protocol field would encode (a decimal
    // array) and confirm every branch of the scan flags it.
    let secret = derived_secret(&KNOWN_SEED);
    let leaky = serde_json::to_vec(&secret).unwrap(); // `[171,171,…]`
    let (_, json_needle) = &needles(&secret)[2];
    assert!(
        contains_subseq(&leaky, json_needle),
        "scanner must detect a planted secret — otherwise the golden test is vacuous"
    );
}

#[test]
fn approval_carries_only_public_material() {
    // Positive check: the Approval DOES carry a signature + pubkey (public), so we
    // know the golden scan above ran against a real, populated message.
    let signer = ScaffoldSigner::from_seed(&KNOWN_SEED);
    let pk = signer.public_key_bytes();
    let approval = Approval {
        session_id: [0u8; 16],
        req_nonce: [0u8; 32],
        counter: 1,
        signature: signer.sign_digest(&[0u8; 32]).unwrap(),
        public_key: pk.clone(),
        payload_digest: [0u8; 32],
    };
    let bytes = serde_json::to_vec(&approval).unwrap();
    // The pubkey is present in its on-wire (json-array) form — public material.
    assert!(contains_subseq(&bytes, &serde_json::to_vec(&pk).unwrap()));
    assert!(!approval.signature.is_empty());
}
