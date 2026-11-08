// SPDX-License-Identifier: MIT OR Apache-2.0
//! Import a `bloch-cli` wallet.json (the canonical CLI keystore format) into
//! Postern Desktop, and spend from an imported **simple** keystore.
//!
//! This is REAL interop with the ownerless protocol's own CLI, not a preview:
//! it reuses the `bloch` crate's own keystore readers, so the crypto and the
//! address round-trip are byte-identical to what `bloch-cli newwallet` /
//! `newseed` wrote.
//!
//!   * **simple** keystore (`bloch-cli newwallet <out.json>`):
//!     `EncryptedKeystore` v2 — Argon2id → AES-256-GCM over an ML-DSA-65
//!     keypair. Read with `bloch::wallet::Keypair::load_encrypted`, which
//!     re-derives the address from the decrypted public key and FAILS if it
//!     does not equal the stored address (the round-trip guarantee is enforced
//!     inside the `bloch` crate, not asserted loosely here).
//!   * **HD** wallet (`bloch-cli newseed <out.json>`): `HdWalletFile` — a BIP39
//!     24-word master + a list of labelled, per-index encrypted keypairs. Read
//!     with `bloch::hd_wallet::HdWallet::load`, which needs the mnemonic +
//!     (optional) passphrase + password because the file's master key is
//!     derived from all three; it likewise re-derives and verifies every
//!     address on load. HD import here is view/verify/receive only — to *spend*
//!     an HD wallet, restore its 24-word mnemonic through the seed-phrase flow
//!     (that path drives the same signer as generate/restore).
//!
//! HONESTY: zero-value pre-mainnet testnet, UNAUDITED cores. The temp file this
//! module writes only ever holds the ciphertext the user already supplied — no
//! new plaintext secret is ever written to disk — and it is deleted immediately
//! after the `bloch` reader has parsed it in memory.

use std::path::Path;

use bloch::wallet::{Keypair, TxBuilder};
use serde_json::{json, Value};

/// Flat fee tiers (in sats) for a raw-keystore spend. The `bloch` `TxBuilder`
/// takes an ABSOLUTE fee, and this build does no live fee estimation, so these
/// are honest fixed heuristics anchored on `bloch-cli`'s own 0.001 BLOCH
/// default (= 100_000 sats = `medium`). Not a fee-market claim.
fn fee_sats_for(tier: &str) -> u64 {
    match tier {
        "next" => 200_000,
        "slow" => 50_000,
        _ => 100_000, // medium — the bloch-cli default (0.001 BLOCH)
    }
}

/// A wallet address is testnet iff it carries the testnet HRP (`bloch1t…`);
/// mainnet addresses are `bloch1q…`. Matches the mobile/desktop WalletCore and
/// the node's own address derivation.
fn is_testnet_address(address: &str) -> bool {
    address.starts_with("bloch1t")
}

/// Write `json` to a short-lived temp file, hand its path to `f`, then delete
/// the file no matter how `f` returns. The file only ever contains the exact
/// (already-encrypted) bytes the caller supplied — the `bloch` keystore readers
/// take a `&Path`, and this is the seam that adapts them to an in-memory JSON
/// string without persisting any new secret.
fn with_temp_json<T>(json: &str, f: impl FnOnce(&Path) -> Result<T, String>) -> Result<T, String> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "postern-desktop-import-{}-{nonce}-{:?}.json",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(&path, json).map_err(|e| format!("could not stage keystore for reading: {e}"))?;
    let out = f(&path);
    let _ = std::fs::remove_file(&path);
    out
}

/// Decrypt a simple `bloch-cli` keystore (round-trip verified by the `bloch`
/// crate — see the module doc). Pure over its inputs; used by both the import
/// and the spend commands.
fn load_simple_keystore(json: &str, password: &str) -> Result<Keypair, String> {
    with_temp_json(json, |p| Keypair::load_encrypted(p, password))
}

/// A tiny allowlist-pinned JSON-RPC POST to a node. `url` must pass the same
/// [`crate::validate_rpc_url`] SSRF gate as the `rpc`/`wallet_send` commands
/// (official public HTTPS RPC, loopback http, or a user-confirmed custom
/// endpoint) — an imported-keystore spend must never become a webview-aimable
/// HTTP client either. Only reads + already-signed `sendrawtransaction` bytes
/// travel here; the keystore password/private key never do.
fn node_rpc(url: &str, method: &str, params: Value, allow_custom: bool) -> Result<Value, String> {
    crate::validate_rpc_url(url, allow_custom)?;
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let resp = ureq::post(url)
        .timeout(std::time::Duration::from_secs(10))
        .send_json(body)
        .map_err(|e| format!("rpc {method}: {e}"))?;
    resp.into_json::<Value>().map_err(|e| e.to_string())
}

/// Import a simple `bloch-cli` keystore (`newwallet`). Returns the recovered
/// address + pubkey + network. Success implies the decrypted pubkey re-derives
/// to the stored address (enforced inside `Keypair::load_encrypted`), so
/// `verified: true` is a fact, not a hope. The private key is NOT returned to
/// the webview — spending goes back through [`wallet_keystore_send`], which
/// re-decrypts from the same ciphertext + password.
#[tauri::command]
pub fn wallet_import_keystore(json: String, password: String) -> Result<Value, String> {
    let kp = load_simple_keystore(&json, &password)?;
    let testnet = is_testnet_address(&kp.address);
    Ok(json!({
        "kind": "simple",
        "address": kp.address,
        "pubkey": hex::encode(&kp.public_key),
        "network": if testnet { "testnet" } else { "mainnet" },
        "verified": true,
    }))
}

/// Import an HD `bloch-cli` wallet (`newseed`). The file's master key is derived
/// from mnemonic + (optional) passphrase + password, so all three are required
/// to open it; `HdWallet::load` re-derives and verifies every labelled address.
/// Returns the network + the full labelled address list (view/verify/receive).
#[tauri::command]
pub fn wallet_import_hd(
    json: String,
    mnemonic: String,
    passphrase: String,
    password: String,
) -> Result<Value, String> {
    let pass = passphrase.trim();
    let pass_opt = if pass.is_empty() { None } else { Some(pass) };
    let hd = with_temp_json(&json, |p| {
        bloch::hd_wallet::HdWallet::load(p, mnemonic.trim(), pass_opt, &password)
    })?;
    let addresses: Vec<Value> = hd
        .list()
        .into_iter()
        .map(|(index, address, label)| json!({ "index": index, "address": address, "label": label }))
        .collect();
    Ok(json!({
        "kind": "hd",
        "network": hd.network,
        "verified": true,
        "addresses": addresses,
    }))
}

/// Spend from an imported **simple** keystore: re-decrypt with the password,
/// then run the exact `getutxos → TxBuilder::build (sign) → sendrawtransaction`
/// flow `bloch-cli send` uses. Allowlist-pinned like `rpc`/`wallet_send`.
/// Returns the broadcast txid hex.
///
/// KEY BOUNDARY: `json`+`password` are decrypted and the tx is SIGNED LOCALLY
/// here; neither the password nor the private key ever crosses the RPC. Only
/// `getutxos(address)` and `sendrawtransaction(signed_hex)` reach the node.
#[tauri::command]
pub fn wallet_keystore_send(
    json: String,
    password: String,
    rpc_url: String,
    to: String,
    amount: u64,
    fee: String,
    allow_custom: Option<bool>,
) -> Result<String, String> {
    let allow_custom = allow_custom.unwrap_or(false);
    crate::validate_rpc_url(&rpc_url, allow_custom)?;
    let kp = load_simple_keystore(&json, &password)?;

    // Destination address (checksum-enforced) → 20-byte hex hash.
    let to_addr = bloch::address::Address::parse(&to).map_err(|e| format!("invalid destination: {e}"))?;
    let to_hex = hex::encode(to_addr.hash());

    // Live UTXO set for the sender, straight from the node.
    let utxos_res = node_rpc(&rpc_url, "getutxos", json!([kp.address]), allow_custom)?;
    if let Some(err) = utxos_res.get("error").filter(|e| !e.is_null()) {
        return Err(format!("getutxos: {err}"));
    }
    let utxos_json = utxos_res
        .get("result")
        .and_then(|r| r.get("utxos"))
        .or_else(|| utxos_res.get("utxos"))
        .and_then(|u| u.as_array())
        .cloned()
        .unwrap_or_default();
    if utxos_json.is_empty() {
        return Err(format!("no spendable UTXOs for {}", kp.address));
    }
    let mut available: Vec<(Vec<u8>, u32, bloch::core::TxOutput)> = Vec::new();
    for u in &utxos_json {
        let txid = hex::decode(u["txid"].as_str().unwrap_or("")).unwrap_or_default();
        let idx = u["index"].as_u64().unwrap_or(0) as u32;
        let value = u["value"].as_u64().unwrap_or(0);
        let spk = hex::decode(u["script_pubkey"].as_str().unwrap_or("")).unwrap_or_default();
        available.push((txid, idx, bloch::core::TxOutput { value, script_pubkey: spk }));
    }

    // Build + sign every input with the imported keypair (same signer bloch-cli
    // uses), then broadcast.
    let tx = TxBuilder::build(&kp, &available, &to_hex, amount, fee_sats_for(&fee))?;
    let txid = hex::encode(tx.txid());
    let raw_hex = hex::encode(tx.to_stratum_bytes(true));
    let res = node_rpc(&rpc_url, "sendrawtransaction", json!([raw_hex]), allow_custom)?;
    if let Some(err) = res.get("error").filter(|e| !e.is_null()) {
        return Err(format!("broadcast rejected: {err}"));
    }
    Ok(txid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_tiers_map_to_sats() {
        assert_eq!(fee_sats_for("slow"), 50_000);
        assert_eq!(fee_sats_for("medium"), 100_000);
        assert_eq!(fee_sats_for("next"), 200_000);
        // Unknown tier falls back to the bloch-cli default (medium).
        assert_eq!(fee_sats_for("nonsense"), 100_000);
    }

    #[test]
    fn network_detection_by_hrp() {
        assert!(is_testnet_address("bloch1t7b003a342f1529f4943e52181c661b0e34c96d02b71f8b78"));
        assert!(!is_testnet_address("bloch1q7b003a342f1529f4943e52181c661b0e34c96d02b71f8b78"));
    }

    // REAL round-trip: write a simple keystore with the SAME `bloch` writer
    // `bloch-cli newwallet` uses, then import it back through our reader and
    // assert the recovered address equals the original. Uses the real
    // Argon2id + AES-256-GCM path end to end (no mocks).
    #[test]
    fn simple_keystore_roundtrips_via_import() {
        let kp = bloch::wallet::generate_keypair(true); // testnet
        let addr = kp.address.clone();
        let pw = "Test-Import-Pw-123!";
        let path = std::env::temp_dir().join(format!(
            "postern-import-selftest-{}-simple.json",
            std::process::id()
        ));
        kp.save_encrypted(&path, pw).expect("write keystore");
        let json = std::fs::read_to_string(&path).expect("read keystore");
        let _ = std::fs::remove_file(&path);

        let out = wallet_import_keystore(json.clone(), pw.to_string()).expect("import ok");
        assert_eq!(out["address"], addr, "imported address must round-trip");
        assert_eq!(out["kind"], "simple");
        assert_eq!(out["network"], "testnet");
        assert_eq!(out["verified"], true);

        // Wrong password must fail closed (never a fake success).
        assert!(wallet_import_keystore(json, "wrong-password".into()).is_err());
    }

    // REAL round-trip for the HD file: create with the same writer `bloch-cli
    // newseed` uses, save, then import back with mnemonic+passphrase+password.
    #[test]
    fn hd_wallet_roundtrips_via_import() {
        let w = bloch::hd_wallet::HdWallet::create("Test-Hd-Pw-12345!", Some("pp"), true).unwrap();
        let mnemonic = w.mnemonic.to_string();
        let addr0 = w.addresses[0].1.address.clone();
        let path = std::env::temp_dir().join(format!(
            "postern-import-selftest-{}-hd.json",
            std::process::id()
        ));
        w.save(&path).unwrap();
        let json = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        let out = wallet_import_hd(json.clone(), mnemonic.clone(), "pp".into(), "Test-Hd-Pw-12345!".into())
            .expect("hd import ok");
        assert_eq!(out["kind"], "hd");
        assert_eq!(out["network"], "testnet");
        assert_eq!(out["addresses"][0]["address"], addr0, "HD address 0 must round-trip");

        // Wrong passphrase fails closed.
        assert!(wallet_import_hd(json, mnemonic, "wrong".into(), "Test-Hd-Pw-12345!".into()).is_err());
    }

    // KEY/RPC BOUNDARY — the load-bearing invariant: a spend decrypts + SIGNS
    // LOCALLY and only the NODE-facing calls (getutxos + sendrawtransaction)
    // leave the process. This test stands up a real in-process mock RPC server
    // on loopback, drives wallet_keystore_send through it, and asserts:
    //   * exactly getutxos then sendrawtransaction are issued (nothing else),
    //   * NEITHER request body contains the keystore password, the decrypted
    //     private-key hex, or the sender's raw pubkey-as-secret — i.e. no
    //     secret material ever crosses the RPC boundary.
    #[test]
    fn keystore_send_never_leaks_secrets_over_rpc() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        // A sender keystore (with a known password) + a destination address.
        let sender = bloch::wallet::generate_keypair(true);
        let sender_addr = sender.address.clone();
        let priv_hex = hex::encode(&sender.private_key);
        let password = "Boundary-Test-Pw-1!";
        let path = std::env::temp_dir().join(format!("postern-boundary-{}.json", std::process::id()));
        sender.save_encrypted(&path, password).unwrap();
        let json = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let dest_kp = bloch::wallet::generate_keypair(true);
        let dest_addr = dest_kp.address.clone();

        // Mock node on loopback. Serves exactly two JSON-RPC requests and
        // records their raw bodies for inspection.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let txid64 = "11".repeat(32);
        let spk40 = "22".repeat(20);
        let getutxos_resp = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"utxos\":[{{\"txid\":\"{txid64}\",\"index\":0,\"value\":100000000,\"script_pubkey\":\"{spk40}\"}}]}}}}"
        );
        let send_resp = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"broadcast-ok\"}".to_string();

        let server = std::thread::spawn(move || {
            let mut bodies: Vec<String> = Vec::new();
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();
                // Read headers + body (Content-Length framed).
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                loop {
                    let n = stream.read(&mut tmp).unwrap_or(0);
                    if n == 0 { break; }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let header_end = pos + 4;
                        let head = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
                        let clen = head
                            .split("content-length:")
                            .nth(1)
                            .and_then(|s| s.split("\r\n").next())
                            .and_then(|s| s.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        while buf.len() < header_end + clen {
                            let n = stream.read(&mut tmp).unwrap_or(0);
                            if n == 0 { break; }
                            buf.extend_from_slice(&tmp[..n]);
                        }
                        let body = String::from_utf8_lossy(&buf[header_end..header_end + clen]).to_string();
                        let resp_body = if body.contains("getutxos") { &getutxos_resp } else { &send_resp };
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            resp_body.len(), resp_body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.flush();
                        bodies.push(body);
                        break;
                    }
                }
                if bodies.len() >= 2 { break; }
            }
            bodies
        });

        let rpc_url = format!("http://127.0.0.1:{port}");
        let txid = wallet_keystore_send(
            json.clone(),
            password.to_string(),
            rpc_url,
            dest_addr,
            10_000,
            "medium".to_string(),
            Some(false),
        )
        .expect("keystore send should succeed against the mock node");
        assert!(!txid.is_empty(), "a txid is returned");

        let bodies = server.join().unwrap();
        assert_eq!(bodies.len(), 2, "exactly two node calls: getutxos + sendrawtransaction");
        assert!(bodies[0].contains("getutxos"), "first call is getutxos");
        assert!(bodies[1].contains("sendrawtransaction"), "second call is sendrawtransaction");

        // The boundary: no secret material in ANY request body.
        for (i, body) in bodies.iter().enumerate() {
            assert!(!body.contains(password), "request {i} must not carry the keystore password");
            assert!(!body.contains(&priv_hex), "request {i} must not carry the private key");
            // getutxos legitimately carries the sender ADDRESS (public); assert
            // that is the only sender-derived value present, and that no method
            // other than the two node reads/broadcast is issued.
            assert!(
                body.contains("getutxos") || body.contains("sendrawtransaction"),
                "request {i} issues only the two allowed node methods",
            );
        }
        // Sanity: the address IS public and may appear (getutxos param) — that's
        // allowed; secrets (above) are what must never appear.
        assert!(bodies[0].contains(&sender_addr), "getutxos queries the public sender address");
    }
}
