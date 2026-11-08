// SPDX-License-Identifier: MIT OR Apache-2.0
//! # postern-signer-conformance — canonical wire-format vectors + drift guard
//!
//! ## SCAFFOLD — pins a REFERENCE (unaudited) protocol, not a deployed one
//!
//! This crate is the **interop contract** for the mobile<->desktop phone-as-signer
//! protocol. It fixes deterministic inputs and pins the exact bytes the two
//! shipped crates ([`postern_pairing`], [`postern_signer_protocol`]) produce, so
//! **any** independent end — a real mobile app, a desktop terminal, a hardware
//! signer, a re-implementation in another language — can conform **byte-for-byte**.
//!
//! Two halves:
//!
//! - [`computed`] recomputes every vector from the crates' **public APIs**.
//! - [`PINNED`] is the golden table. `tests/conformance.rs` asserts
//!   `computed() == PINNED`; if any crate changes a wire format, the build fails.
//!
//! Run `cargo run --bin dump-vectors` to print the whole table (add `--emit` to
//! regenerate the pinned tuples after an intentional, reviewed format change).
//!
//! ### What is pinned (and what is NOT)
//! Everything here is a **public** value: encodings, domain-separated digests,
//! HKDF-derived public ids, and a **deterministic REFERENCE scaffold signature**
//! (explicitly NOT real cryptography — the real signer is the phone's hybrid
//! Falcon‖ML-DSA `WalletCore`, whose Falcon leg is randomized and so is *not*
//! byte-pinnable; its verification is exercised in the e2e-demo instead). **No
//! private key, seed, or session traffic key appears in any vector** — that is
//! structural in the crates, and visibly true here.
//!
//! The randomized parts of the live protocol (the ephemeral KEM keypairs, the
//! per-pairing nonce, the AEAD frame nonces, the real PQ signature) are NOT
//! byte-pinned — only their **formats** and the **deterministic transcript**
//! (channel binding, SAS mapping, signing digests, JSON layout) are.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use postern_pairing::binding::channel_binding;
use postern_pairing::channel::{endpoints, Frame};
use postern_pairing::hybrid::{SessionKey, KEM_CT_LEN, PUBLIC_KEY_LEN};
use postern_pairing::{PairingInit, QrPayload, Sas, PROTOCOL_VERSION};

use postern_signer_protocol::wysiwys::confirmation_fragment;
use postern_signer_protocol::{
    Approval, Chain, LoginChallenge, ScaffoldSigner, SignPayload, SignRequest, TransferIntent,
    WalletSigner, LOGIN_DOMAIN, SIGNER_DOMAIN,
};

/// One pinned wire-format vector. `value` is already stringified: lowercase hex
/// for byte blobs, a fingerprint string for the large structural encodings, or a
/// literal (SAS digits, a JSON body, a domain tag) as noted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vector {
    /// Stable dotted id, e.g. `signer.login.digest`.
    pub name: &'static str,
    /// One-line human note describing what an implementer must reproduce.
    pub note: &'static str,
    /// The canonical, recomputed value.
    pub value: String,
}

// ── Deterministic fixtures (documented so any implementation can reproduce) ────

/// The fixed 32-byte session key used for the SAS + channel-id transcript
/// vectors: every byte `0x5a`.
pub fn fixture_session_key() -> SessionKey {
    Zeroizing::new([0x5au8; 32])
}

/// The fixed 32-byte pairing nonce used for the channel-binding vector: every
/// byte `0x11`.
pub const FIXTURE_NONCE: [u8; 32] = [0x11u8; 32];

/// The fixed anchor public key stand-in for the channel-binding vector: 64 bytes
/// of `0x22`. (The binding is `SHA-256(nonce ‖ pubkey)` over ANY pubkey bytes;
/// this compact input is a reproducible known-answer test of that function.)
pub const FIXTURE_BINDING_PUBKEY: [u8; 64] = [0x22u8; 64];

/// A deterministic `PUBLIC_KEY_LEN`-byte anchor for the QR fixture: byte `i` is
/// `(i % 251)`. Not a real key — a reproducible stand-in that exercises the QR
/// length-value framing at the true anchor size.
pub fn fixture_anchor() -> Vec<u8> {
    (0..PUBLIC_KEY_LEN).map(|i| (i % 251) as u8).collect()
}

/// A deterministic `KEM_CT_LEN`-byte encapsulation for the PairingInit fixture.
pub fn fixture_kem_ct() -> Vec<u8> {
    (0..KEM_CT_LEN).map(|i| ((i + 7) % 251) as u8).collect()
}

/// The 16-byte protocol session id fixture: every byte `0x07`.
pub const FIXTURE_SESSION_ID: [u8; 16] = [0x07u8; 16];

/// The 32-byte request-nonce fixture: every byte `0x05`.
pub const FIXTURE_REQ_NONCE: [u8; 32] = [0x05u8; 32];

/// The canonical wallet-login challenge fixture (consiglio-auth shape).
pub fn fixture_login() -> LoginChallenge {
    LoginChallenge {
        org: "acme-corp".into(),
        user: "alice".into(),
        nonce: [0x11u8; 32],
        issued_at: 1_752_000_000,
    }
}

/// The canonical value-transfer fixture.
pub fn fixture_transfer() -> TransferIntent {
    TransferIntent {
        to_address: "bloch1qdeadbeef".into(),
        amount: 1000,
        fee: 1,
        chain: Chain::Mainnet,
        nonce: [0x09u8; 32],
    }
}

/// The canonical SignRequest fixture (login payload).
pub fn fixture_request() -> SignRequest {
    SignRequest {
        session_id: FIXTURE_SESSION_ID,
        req_nonce: FIXTURE_REQ_NONCE,
        counter: 1,
        payload: SignPayload::Login(fixture_login()).encode(),
    }
}

/// The canonical Approval fixture. The signature/pubkey are fixed PUBLIC
/// placeholders (never real key material) so the JSON layout is pinnable.
pub fn fixture_approval() -> Approval {
    Approval {
        session_id: FIXTURE_SESSION_ID,
        req_nonce: FIXTURE_REQ_NONCE,
        counter: 1,
        signature: vec![0xABu8; 8],
        public_key: vec![0xCDu8; 8],
        payload_digest: fixture_login().signing_digest(),
    }
}

/// The reference scaffold-signer seed (deterministic; NOT a wallet seed).
pub const FIXTURE_SCAFFOLD_SEED: &[u8] = b"postern-conformance-seed:v1";

/// The 32-byte digest the reference scaffold signer signs in its vector.
pub const FIXTURE_SIGN_DIGEST: [u8; 32] = [0x42u8; 32];

// ── Small helpers ─────────────────────────────────────────────────────────────

fn hexs(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// A compact, reproducible fingerprint for a large structural blob:
/// `len=<n> magic=<first8hex> sha256=<hex>`. An implementer reproduces the blob
/// from the documented fixture and checks the same three fields.
fn fingerprint(bytes: &[u8]) -> String {
    let head = &bytes[..bytes.len().min(4)];
    let mut h = Sha256::new();
    h.update(bytes);
    format!(
        "len={} magic={} sha256={}",
        bytes.len(),
        hexs(head),
        hexs(&h.finalize())
    )
}

// ── The vector table (recomputed from the crates) ─────────────────────────────

/// Recompute every conformance vector from the two crates' public APIs, in a
/// stable order. This is the source the drift guard compares against [`PINNED`].
pub fn computed() -> Vec<Vector> {
    let mut v = Vec::new();

    // ---- Pairing (Dev1) ------------------------------------------------------

    // Protocol version byte bound into every KDF transcript + the QR.
    v.push(Vector {
        name: "pairing.protocol_version",
        note: "PROTOCOL_VERSION byte (bump breaks interop)",
        value: PROTOCOL_VERSION.to_string(),
    });

    // QR wire encoding: MAGIC(4) ‖ ver(1) ‖ lv(anchor) ‖ nonce(32) ‖ lv(lan_hint) ‖ lv(identity).
    let qr = QrPayload {
        version: PROTOCOL_VERSION,
        anchor_public: fixture_anchor(),
        nonce: FIXTURE_NONCE,
        lan_hint: "192.168.1.20:47001".into(),
        terminal_identity_pub: b"desktop-identity-pub-key".to_vec(),
    };
    v.push(Vector {
        name: "pairing.qr.encoding",
        note: "QrPayload::to_bytes = PPQR ‖ ver ‖ len16‖anchor ‖ nonce32 ‖ len16‖lan_hint ‖ len16‖identity",
        value: fingerprint(&qr.to_bytes()),
    });

    // PairingInit wire encoding: lv(kem_ct) ‖ lv(identity).
    let init = PairingInit {
        kem_ct: fixture_kem_ct(),
        custodian_identity_pub: b"phone-identity-pub-key".to_vec(),
    };
    v.push(Vector {
        name: "pairing.init.encoding",
        note: "PairingInit::to_bytes = len16‖kem_ct ‖ len16‖custodian_identity",
        value: fingerprint(&init.to_bytes()),
    });

    // Channel binding: SHA-256(nonce ‖ anchor_pubkey).
    v.push(Vector {
        name: "pairing.channel_binding",
        note: "SHA-256(nonce[0x11;32] ‖ pubkey[0x22;64])",
        value: hexs(&channel_binding(&FIXTURE_NONCE, &FIXTURE_BINDING_PUBKEY)),
    });

    // SAS: 6 digits from HKDF-SHA-256(session_key, info="postern-pairing/sas/v1").
    let key = fixture_session_key();
    v.push(Vector {
        name: "pairing.sas.digits",
        note: "Sas::derive(key[0x5a;32]).digits() — HKDF info \"postern-pairing/sas/v1\", be_u32 mod 1e6",
        value: Sas::derive(&key).digits(),
    });
    let zero_key: SessionKey = Zeroizing::new([0x00u8; 32]);
    v.push(Vector {
        name: "pairing.sas.digits_zero_key",
        note: "Sas::derive(key[0x00;32]).digits() — second SAS known-answer",
        value: Sas::derive(&zero_key).digits(),
    });

    // Derived public session id (HKDF info "postern-pairing/session-id/v1").
    let (chan_a, _chan_b) = endpoints(&key);
    v.push(Vector {
        name: "pairing.channel.session_id",
        note: "endpoints(key[0x5a;32]).session_id() — HKDF info \"postern-pairing/session-id/v1\"",
        value: hexs(chan_a.session_id()),
    });

    // Paired-channel frame layout: counter(8, BE) ‖ nonce(24) ‖ aead_ct.
    // Round-trip a known byte string through the parser+serializer to pin it.
    let mut frame_bytes = Vec::new();
    frame_bytes.extend_from_slice(&1u64.to_be_bytes()); // counter = 1
    frame_bytes.extend((0..24u8).map(|i| i.wrapping_mul(9))); // 24-byte nonce
    frame_bytes.extend(std::iter::repeat(0xEEu8).take(20)); // >= 16-byte "ct"
    let reframed = Frame::from_bytes(&frame_bytes)
        .expect("frame parses")
        .to_bytes();
    v.push(Vector {
        name: "pairing.frame.layout",
        note: "Frame::from_bytes→to_bytes round-trip: counter(8 BE) ‖ nonce(24) ‖ aead_ct",
        value: hexs(&reframed),
    });

    // ---- Signer protocol (Dev2) ---------------------------------------------

    v.push(Vector {
        name: "signer.domain.login",
        note: "LOGIN_DOMAIN (byte-identical to consiglio-auth's transcript tag)",
        value: String::from_utf8_lossy(LOGIN_DOMAIN).into_owned(),
    });
    v.push(Vector {
        name: "signer.domain.signer",
        note: "SIGNER_DOMAIN (phone-as-signer request transcript tag)",
        value: String::from_utf8_lossy(SIGNER_DOMAIN).into_owned(),
    });

    // The consiglio-compatible wallet-login signing digest (SHA3-256).
    v.push(Vector {
        name: "signer.login.digest",
        note: "LoginChallenge{org:acme-corp,user:alice,nonce:0x11*32,issued_at:1752000000}.signing_digest()",
        value: hexs(&fixture_login().signing_digest()),
    });
    // The value-transfer signing digest (chain-id folded in).
    v.push(Vector {
        name: "signer.transfer.digest",
        note: "TransferIntent{bloch1qdeadbeef,1000,fee1,mainnet,nonce:0x09*32}.signing_digest()",
        value: hexs(&fixture_transfer().signing_digest()),
    });

    // The transport encoding of a SignPayload (serde_json).
    v.push(Vector {
        name: "signer.payload.login.json",
        note: "SignPayload::Login(fixture).encode() — serde_json bytes on the wire",
        value: String::from_utf8_lossy(&SignPayload::Login(fixture_login()).encode()).into_owned(),
    });
    v.push(Vector {
        name: "signer.payload.transfer.json",
        note: "SignPayload::Transfer(fixture).encode() — serde_json bytes on the wire",
        value: String::from_utf8_lossy(&SignPayload::Transfer(fixture_transfer()).encode())
            .into_owned(),
    });

    // The full SignRequest and Approval JSON (the exact serde_json the protocol
    // sends). `payload`/`signature`/`public_key` are byte arrays in JSON.
    v.push(Vector {
        name: "signer.request.json",
        note: "serde_json::to_vec(&SignRequest fixture) — DESKTOP→PHONE wire body",
        value: String::from_utf8_lossy(
            &serde_json::to_vec(&fixture_request()).expect("request serializes"),
        )
        .into_owned(),
    });
    v.push(Vector {
        name: "signer.approval.json",
        note: "serde_json::to_vec(&Approval fixture) — PHONE→DESKTOP wire body (public sig/pk placeholders)",
        value: String::from_utf8_lossy(
            &serde_json::to_vec(&fixture_approval()).expect("approval serializes"),
        )
        .into_owned(),
    });

    // The protocol frame codec: MAGIC "PSG1" ‖ len(4, LE) ‖ body.
    v.push(Vector {
        name: "signer.frame.codec",
        note: "channel::frame(b\"hello\") = PSG1 ‖ len32_le ‖ body",
        value: hexs(&postern_signer_protocol::channel::frame(b"hello").expect("frame")),
    });

    // The WYSIWYS confirmation fragment shown on BOTH screens.
    v.push(Vector {
        name: "signer.wysiwys.fragment",
        note: "confirmation_fragment(session[0x07;16], nonce[0x05;32]) — SHA3-256, first 3 bytes hex",
        value: confirmation_fragment(FIXTURE_SESSION_ID, &FIXTURE_REQ_NONCE),
    });

    // The deterministic REFERENCE scaffold signature (NOT real cryptography).
    let signer = ScaffoldSigner::from_seed(FIXTURE_SCAFFOLD_SEED);
    v.push(Vector {
        name: "signer.scaffold.public_key",
        note: "ScaffoldSigner::from_seed(seed).public_key_bytes() — SHA3(\"scaffold-pubkey\"‖secret)",
        value: hexs(&signer.public_key_bytes()),
    });
    v.push(Vector {
        name: "signer.scaffold.address",
        note: "ScaffoldSigner::from_seed(seed).address()",
        value: signer.address(),
    });
    v.push(Vector {
        name: "signer.scaffold.signature",
        note: "ScaffoldSigner::from_seed(seed).sign_digest([0x42;32]) — SHA3(\"scaffold-sig:v1\"‖secret‖digest)",
        value: hexs(&signer.sign_digest(&FIXTURE_SIGN_DIGEST).expect("sign")),
    });

    v
}

/// The golden table. Generated by `dump-vectors --emit` and pasted here; the
/// drift guard in `tests/conformance.rs` asserts [`computed`] reproduces it
/// exactly. A mismatch is either a protocol change (bump a version + re-emit,
/// deliberately) or an accidental wire-format regression (fix the crate).
pub const PINNED: &[(&str, &str)] = &[
    // @@PINNED_START@@ (regenerate with `cargo run --bin dump-vectors -- --emit`)
    ("pairing.protocol_version", "1"),
    ("pairing.qr.encoding", "len=1685 magic=50505152 sha256=dc5b7c6c378ef9acd58dcac833df7540b552b2298c4b8997393638f33e7d7295"),
    ("pairing.init.encoding", "len=1626 magic=06400708 sha256=3004d0dc132a60584631e2486afd4c8947798ccde3c3542d1ec90240b614b09d"),
    ("pairing.channel_binding", "d6a6a0ebd329253d2887e1bfd5d0705f7a501ba95cb29892f271c4b45741dc8c"),
    ("pairing.sas.digits", "966542"),
    ("pairing.sas.digits_zero_key", "097173"),
    ("pairing.channel.session_id", "3fd524cd7cf56f4b1a0c4178230b4893d234960842163711ae0274ff1caabaef"),
    ("pairing.frame.layout", "00000000000000010009121b242d363f48515a636c757e879099a2abb4bdc6cfeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
    ("signer.domain.login", "consiglio:wallet-login:v1"),
    ("signer.domain.signer", "postern:signer-protocol:v1"),
    ("signer.login.digest", "417d61ab026d895002b2058b05c912482a2532ce4c0662020a8b20a4967fee68"),
    ("signer.transfer.digest", "0e4bd4d5cc9219bdfbef3b5283f56fbcfbacaeb9e3cbf1d3ef5a3cc4242ec468"),
    ("signer.payload.login.json", "{\"Login\":{\"org\":\"acme-corp\",\"user\":\"alice\",\"nonce\":[17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17],\"issued_at\":1752000000}}"),
    ("signer.payload.transfer.json", "{\"Transfer\":{\"to_address\":\"bloch1qdeadbeef\",\"amount\":1000,\"fee\":1,\"chain\":\"Mainnet\",\"nonce\":[9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9]}}"),
    ("signer.request.json", "{\"session_id\":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],\"req_nonce\":[5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5],\"counter\":1,\"payload\":[123,34,76,111,103,105,110,34,58,123,34,111,114,103,34,58,34,97,99,109,101,45,99,111,114,112,34,44,34,117,115,101,114,34,58,34,97,108,105,99,101,34,44,34,110,111,110,99,101,34,58,91,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,44,49,55,93,44,34,105,115,115,117,101,100,95,97,116,34,58,49,55,53,50,48,48,48,48,48,48,125,125]}"),
    ("signer.approval.json", "{\"session_id\":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],\"req_nonce\":[5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5],\"counter\":1,\"signature\":[171,171,171,171,171,171,171,171],\"public_key\":[205,205,205,205,205,205,205,205],\"payload_digest\":[65,125,97,171,2,109,137,80,2,178,5,139,5,201,18,72,42,37,50,206,76,6,98,2,10,139,32,164,150,127,238,104]}"),
    ("signer.frame.codec", "505347310500000068656c6c6f"),
    ("signer.wysiwys.fragment", "519bf8"),
    ("signer.scaffold.public_key", "a740d59311b6337b5b0490bdb000203795fc6d7d29505f001779d49e81f8b9d5"),
    ("signer.scaffold.address", "bloch1qa740d59311b6337b5b04"),
    ("signer.scaffold.signature", "9b3f0e38b2f998196ffccc0551a358b248254be497fba23c9cde0fd58b623e70"),
    // @@PINNED_END@@
];

/// Look up a pinned value by name (used by the checker and the dumper).
pub fn pinned(name: &str) -> Option<&'static str> {
    PINNED.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}
