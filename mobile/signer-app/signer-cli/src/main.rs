// SPDX-License-Identifier: MIT OR Apache-2.0
//! signer-cli — a tiny **stdio JSON** bridge that DRIVES `postern-mobile-signer`.
//!
//! This is the thin, honest seam between the reference web UI (which cannot call
//! Rust directly) and the real phone-side engine. It reimplements **no** crypto:
//! it holds a live [`MobileSigner`] (the phone) plus a [`DesktopRequester`] (a
//! local stand-in for the key-less terminal) over the protocol's in-process
//! loopback, and turns line-delimited JSON commands into calls on that engine:
//!
//! ```text
//!   request_login / request_transfer  (desktop stand-in) -> a REAL request frame
//!   receive_frame                      -> the WYSIWYS Prompt (tier + sentence)
//!   approve(PresenceProof) / decline   -> the Approval frame (hybrid signature)
//! ```
//!
//! Everything consequential — the replay guard, the three consequence tiers, the
//! WYSIWYS sentence parsed from the ACTUAL bytes, and the Falcon‖ML-DSA signature
//! — comes from the frozen crates via `postern-mobile-signer`.
//!
//! ## RAILS (carried here, not rounded off)
//! - REFERENCE DRIVER, **not a shipped phone app**. The mobile OS image is
//!   **UNBOOTED**. This is a driver you run on a workstation.
//! - The key/seed **never leaves the device**: only public outputs (address,
//!   public key, signature) ever cross the JSON boundary — the engine's types
//!   make that structural.
//! - **Software keystore, NOT hardware.** The PQ secret is in RAM at sign time.
//! - **Per-sign user presence; no blanket auto-approve.** Each `approve` carries
//!   a [`PresenceProof`] bound to that request's own nonce.
//! - Unaudited scaffold. The coin is **not a security**.

use std::io::{self, BufRead, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use postern_mobile_signer::protocol::{
    fresh_nonce, Chain, Channel, DesktopRequester, LoginChallenge, LoopEnd, SentRequest,
    SignPayload, TransferIntent,
};
use postern_mobile_signer::{MobileSigner, PresenceMethod, PresenceProof, WalletCoreSigner};
use serde_json::{json, Value};

/// The whole driver state: the phone engine, the key-less desktop stand-in, the
/// in-process loopback that carries frames between them, and the last request the
/// desktop sent (so a returned approval can be matched to it).
struct Driver {
    signer: MobileSigner,
    requester: DesktopRequester,
    desk: LoopEnd,
    phone: LoopEnd,
    last_sent: Option<SentRequest>,
    testnet: bool,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn to_16(bytes: &[u8]) -> Result<[u8; 16], String> {
    bytes
        .try_into()
        .map_err(|_| format!("session id must be 16 bytes, got {}", bytes.len()))
}

fn to_32(bytes: &[u8]) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| format!("value must be 32 bytes, got {}", bytes.len()))
}

fn method_of(s: &str) -> Result<PresenceMethod, String> {
    match s {
        "biometric" | "Biometric" => Ok(PresenceMethod::Biometric),
        "device_pin" | "DevicePin" | "pin" => Ok(PresenceMethod::DevicePin),
        other => Err(format!("unknown presence method: {other}")),
    }
}

impl Driver {
    /// `init`: build the phone engine from a seed, bind the key-less desktop
    /// stand-in to the same session, and open the loopback between them.
    fn init(v: &Value) -> Result<(Driver, Value), String> {
        let testnet = v.get("testnet").and_then(Value::as_bool).unwrap_or(true);
        let peer = v
            .get("peer")
            .and_then(Value::as_str)
            .unwrap_or("Tiago's ThinkPad")
            .to_string();

        // Seed: 32+ bytes of hex, or a deterministic reference default.
        let seed = match v.get("seed_hex").and_then(Value::as_str) {
            Some(h) if !h.is_empty() => {
                hex::decode(h).map_err(|e| format!("bad seed_hex: {e}"))?
            }
            _ => vec![9u8; 32],
        };

        // Session id: 16 bytes of hex, or a deterministic reference default.
        let session = match v.get("session_hex").and_then(Value::as_str) {
            Some(h) if !h.is_empty() => {
                to_16(&hex::decode(h).map_err(|e| format!("bad session_hex: {e}"))?)?
            }
            _ => [7u8; 16],
        };

        let core = WalletCoreSigner::from_seed_bytes(&seed, testnet)
            .map_err(|e| format!("wallet: {e}"))?;
        let signer = MobileSigner::new(core, session, peer.clone());
        let address = signer.address();

        let requester = DesktopRequester::new(session);
        let (desk, phone) = postern_mobile_signer::protocol::loopback();

        let out = json!({
            "ok": true,
            "address": address,
            "session_hex": hex::encode(session),
            "peer": peer,
            "network": if testnet { "testnet" } else { "mainnet" },
        });
        Ok((
            Driver {
                signer,
                requester,
                desk,
                phone,
                last_sent: None,
                testnet,
            },
            out,
        ))
    }

    /// `request_login`: the DESKTOP stand-in composes a real, domain-separated
    /// wallet-login challenge and sends it over the loopback. Returns the exact
    /// request frame the phone will process — nothing is signed here.
    fn request_login(&mut self, v: &Value) -> Result<Value, String> {
        let org = v.get("org").and_then(Value::as_str).unwrap_or("acme").to_string();
        let user = v.get("user").and_then(Value::as_str).unwrap_or("alice").to_string();
        let challenge = LoginChallenge {
            org,
            user,
            nonce: fresh_nonce(),
            issued_at: now_unix(),
        };
        let sent = self
            .requester
            .request_login(&mut self.desk, &challenge)
            .map_err(|e| format!("request_login: {e}"))?;
        let frame = self.phone.recv().map_err(|e| format!("transport: {e}"))?;
        self.last_sent = Some(sent);
        Ok(json!({ "ok": true, "frame_hex": hex::encode(frame), "kind": "login" }))
    }

    /// `request_transfer`: the DESKTOP stand-in composes a value transfer (the
    /// highest consequence tier) and sends it. Reference-only — proves the same
    /// path carries the irreversible tier. Chain comes from the phone's network.
    fn request_transfer(&mut self, v: &Value) -> Result<Value, String> {
        let to_address = v
            .get("to_address")
            .and_then(Value::as_str)
            .unwrap_or("bloch1tqe...reference")
            .to_string();
        let amount = v.get("amount").and_then(Value::as_u64).unwrap_or(1000);
        let fee = v.get("fee").and_then(Value::as_u64).unwrap_or(10);
        let intent = TransferIntent {
            to_address,
            amount,
            fee,
            chain: if self.testnet { Chain::Testnet } else { Chain::Mainnet },
            nonce: fresh_nonce(),
        };
        let sent = self
            .requester
            .request(&mut self.desk, SignPayload::Transfer(intent))
            .map_err(|e| format!("request_transfer: {e}"))?;
        let frame = self.phone.recv().map_err(|e| format!("transport: {e}"))?;
        self.last_sent = Some(sent);
        Ok(json!({ "ok": true, "frame_hex": hex::encode(frame), "kind": "transfer" }))
    }

    /// `receive_frame`: feed the raw frame to the phone engine. Runs the replay
    /// guard + payload decode + WYSIWYS render; returns the Prompt (fail-closed).
    fn receive_frame(&mut self, v: &Value) -> Result<Value, String> {
        let frame_hex = v
            .get("frame_hex")
            .and_then(Value::as_str)
            .ok_or("receive_frame needs frame_hex")?;
        let frame = hex::decode(frame_hex).map_err(|e| format!("bad frame_hex: {e}"))?;
        let p = self
            .signer
            .receive_frame(&frame)
            .map_err(|e| format!("{e}"))?;
        let tier = match p.tier {
            postern_mobile_signer::Tier::SilentReadOnly => "SilentReadOnly",
            postern_mobile_signer::Tier::SingleTap => "SingleTap",
            postern_mobile_signer::Tier::ExplicitReview => "ExplicitReview",
        };
        Ok(json!({
            "ok": true,
            "prompt": {
                "tier": tier,
                "sentence": p.sentence,
                "can_move_funds": p.can_move_funds,
                "peer_device": p.peer_device,
                "confirmation_fragment": p.confirmation_fragment,
                "req_nonce_hex": p.req_nonce_hex,
                "disclosure": p.disclosure,
            }
        }))
    }

    /// `approve`: per-sign presence. The proof is bound to THIS request's nonce
    /// (no blanket auto-approve). Signs, then delivers the approval to the desktop
    /// stand-in and matches it — surfacing the public signature/pubkey only.
    fn approve(&mut self, v: &Value) -> Result<Value, String> {
        let req_nonce_hex = v
            .get("req_nonce_hex")
            .and_then(Value::as_str)
            .ok_or("approve needs req_nonce_hex")?;
        let method = method_of(v.get("method").and_then(Value::as_str).unwrap_or("biometric"))?;
        let nonce = to_32(&hex::decode(req_nonce_hex).map_err(|e| format!("bad nonce hex: {e}"))?)?;
        let proof = PresenceProof::granted(nonce, method);
        let frame = self.signer.approve(proof).map_err(|e| format!("{e}"))?;
        self.deliver_and_match(frame)
    }

    /// `approve_single_tap`: prompt-free approval IFF a live, un-revoked grant
    /// covers this single-tap login. Never covers a value transfer (the engine
    /// refuses). Still not a blanket token — the grant is time-boxed + revocable.
    fn approve_single_tap(&mut self, v: &Value) -> Result<Value, String> {
        let now = v.get("now_unix").and_then(Value::as_i64).unwrap_or_else(now_unix);
        let frame = self
            .signer
            .approve_single_tap_by_grant(now)
            .map_err(|e| format!("{e}"))?;
        self.deliver_and_match(frame)
    }

    /// Send the approval frame back over the loopback and have the desktop
    /// stand-in match it to the request it sent. Only public data crosses back.
    fn deliver_and_match(&mut self, frame: Vec<u8>) -> Result<Value, String> {
        let sent = self.last_sent.clone().ok_or("no request was sent")?;
        self.phone.send(&frame).map_err(|e| format!("transport: {e}"))?;
        let approval = self
            .requester
            .recv_approval(&mut self.desk, &sent)
            .map_err(|e| format!("desktop match: {e}"))?;
        self.last_sent = None;
        Ok(json!({
            "ok": true,
            "approval_frame_hex": hex::encode(&frame),
            "matched": true,
            "signature_hex": hex::encode(&approval.signature),
            "public_key_hex": hex::encode(&approval.public_key),
            "payload_digest_hex": hex::encode(approval.payload_digest),
            "counter": approval.counter,
        }))
    }

    /// `decline`: nothing is signed; the replay guard is not committed, so the
    /// request never advances the sequence.
    fn decline(&mut self) -> Result<Value, String> {
        self.signer.decline().map_err(|e| format!("{e}"))?;
        self.last_sent = None;
        Ok(json!({ "ok": true, "declined": true }))
    }

    fn set_login_grant(&mut self, v: &Value) -> Result<Value, String> {
        let org = v.get("org").and_then(Value::as_str).unwrap_or("acme").to_string();
        let expires = v
            .get("expires_at_unix")
            .and_then(Value::as_i64)
            .unwrap_or_else(|| now_unix() + 22 * 60);
        self.signer.set_login_grant(org, expires);
        Ok(json!({ "ok": true, "grant_expires_at_unix": expires }))
    }

    fn revoke_grant(&mut self) -> Result<Value, String> {
        self.signer.revoke_grant();
        Ok(json!({ "ok": true, "revoked": true }))
    }

    fn address(&self) -> Result<Value, String> {
        Ok(json!({ "ok": true, "address": self.signer.address() }))
    }

    fn dispatch(driver: &mut Option<Driver>, v: &Value) -> Value {
        let cmd = match v.get("cmd").and_then(Value::as_str) {
            Some(c) => c,
            None => return json!({ "ok": false, "error": "missing cmd" }),
        };

        // `init` (re)creates the driver; every other command needs one.
        if cmd == "init" {
            return match Driver::init(v) {
                Ok((d, out)) => {
                    *driver = Some(d);
                    out
                }
                Err(e) => json!({ "ok": false, "error": e }),
            };
        }
        if cmd == "ping" {
            return json!({ "ok": true, "pong": true });
        }

        let d = match driver.as_mut() {
            Some(d) => d,
            None => return json!({ "ok": false, "error": "call init first" }),
        };

        let res = match cmd {
            "request_login" => d.request_login(v),
            "request_transfer" => d.request_transfer(v),
            "receive_frame" => d.receive_frame(v),
            "approve" => d.approve(v),
            "approve_single_tap" => d.approve_single_tap(v),
            "decline" => d.decline(),
            "set_login_grant" => d.set_login_grant(v),
            "revoke_grant" => d.revoke_grant(),
            "address" => d.address(),
            other => Err(format!("unknown cmd: {other}")),
        };
        match res {
            Ok(out) => out,
            Err(e) => json!({ "ok": false, "error": e }),
        }
    }
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut driver: Option<Driver> = None;

    // Announce readiness so the Node bridge can distinguish "spawned + linked"
    // from "binary missing".
    let hello = json!({
        "ok": true,
        "ready": true,
        "engine": "postern-mobile-signer",
        "note": "REFERENCE DRIVER — mobile image UNBOOTED; software keystore, not hardware."
    });
    let _ = writeln!(stdout, "{hello}");
    let _ = stdout.flush();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let out = match serde_json::from_str::<Value>(trimmed) {
            Ok(v) => Driver::dispatch(&mut driver, &v),
            Err(e) => json!({ "ok": false, "error": format!("bad json: {e}") }),
        };
        if writeln!(stdout, "{out}").is_err() {
            break;
        }
        let _ = stdout.flush();
    }
}
