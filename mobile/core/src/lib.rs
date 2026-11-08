//! Postern Wallet — the wallet engine (a Postern Labs product).
//!
//! Byte-compatible with the ownerless Bloch-SIS-PoW protocol (crate: `bloch-mobile`).
//!
//! The shared Rust engine behind the Android/iOS apps. It is **pure** (no
//! network, no disk) — the native side (OkHttp / URLSession, StrongBox /
//! Secure Enclave) does I/O and hardware; this crate does wallet crypto, tx
//! signing, JSON-RPC request/response shaping, and the device-attestation
//! challenge plumbing. Exposed to Kotlin/Swift via UniFFI.
//!
//! Correctness: it reuses the node's exact `bloch_crypto::crypto` + `bloch_crypto::wallet`
//! logic, so addresses/signatures are byte-compatible (guarded by a golden test).

use bloch_crypto::crypto;
use bloch_crypto::wallet::SeedPhrase;
use serde_json::json;

// UniFFI convergence (Dev-F1): this crate no longer registers its own UniFFI
// scaffolding and no longer carries its own `mod ffi` surface. `WalletCore`
// below stays a PURE Rust engine — used by the desktop app and by the golden
// byte-identity test — while the single shipped FFI surface for the whole
// product suite is `crates/postern-sdk`, which folds this `WalletCore` in
// (with `default-features = false`) and owns the ONE
// `uniffi::setup_scaffolding!()`. So exactly one scaffolding ships. The old
// `mod ffi` here (a second `setup_scaffolding!`) is superseded verbatim by
// `postern-sdk/src/wallet.rs` and has been removed.

/// A light wallet: the hybrid Falcon‖ML-DSA keypair + its address.
pub struct WalletCore {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
    address: String,
    /// Master seed — enables diversified (unlinkable) address rotation.
    seed: Vec<u8>,
    testnet: bool,
}

impl WalletCore {
    /// New random wallet. Returns the wallet and its BIP39 mnemonic phrase —
    /// the ONLY backup, show it once and let the user store it securely.
    pub fn generate(testnet: bool) -> Result<(WalletCore, String), String> {
        let m = SeedPhrase::generate().map_err(|e| e.to_string())?;
        let phrase = m.words().join(" ");
        let w = Self::from_mnemonic(&phrase, testnet)?;
        Ok((w, phrase))
    }

    /// Restore from a BIP39 mnemonic phrase.
    pub fn from_mnemonic(phrase: &str, testnet: bool) -> Result<WalletCore, String> {
        let m = SeedPhrase::parse(phrase).map_err(|e| e.to_string())?;
        Self::from_seed_bytes(&m.to_seed_bytes(), testnet)
    }

    /// Restore from raw seed bytes (>=32). Deterministic — same seed → same key.
    pub fn from_seed_bytes(seed: &[u8], testnet: bool) -> Result<WalletCore, String> {
        let (pk, sk) = crypto::generate_keypair_from_seed(seed).map_err(|e| e.to_string())?;
        let address = crypto::address_from_pubkey(&pk, testnet);
        Ok(WalletCore { public_key: pk, secret_key: sk, address, seed: seed.to_vec(), testnet })
    }

    pub fn address(&self) -> String { self.address.clone() }

    // (secret_key + seed are wiped on drop — see the Drop impl below.)

    /// A diversified (unlinkable) receiving address for `index`. Index 0 is the
    /// base address; 1, 2, … are independent, on-chain-unlinkable addresses from
    /// the same seed. **Privacy: rotate one per receive, never reuse.**
    pub fn address_at(&self, index: u32) -> Result<String, String> {
        if index == 0 {
            Ok(self.address.clone())
        } else {
            crypto::diversified_address(&self.seed, index, self.testnet).map_err(|e| e.to_string())
        }
    }

    /// Sign with the diversified keypair for `index` (to spend from a diversified
    /// address). Index 0 uses the base key.
    pub fn sign_at(&self, index: u32, message_hex: &str) -> Result<String, String> {
        let msg = hex::decode(message_hex).map_err(|e| format!("bad message hex: {}", e))?;
        let sk = if index == 0 {
            self.secret_key.clone()
        } else {
            crypto::diversified_keypair(&self.seed, index).map_err(|e| e.to_string())?.1
        };
        Ok(hex::encode(crypto::sign(&sk, &msg).map_err(|e| e.to_string())?))
    }
    pub fn public_key_hex(&self) -> String { hex::encode(&self.public_key) }

    /// Sign an arbitrary message (hex in → hybrid signature hex out). The tx
    /// sighash is computed native-side or by a future `sign_tx` helper.
    pub fn sign_hex(&self, message_hex: &str) -> Result<String, String> {
        let msg = hex::decode(message_hex).map_err(|e| format!("bad message hex: {}", e))?;
        let sig = crypto::sign(&self.secret_key, &msg).map_err(|e| e.to_string())?;
        Ok(hex::encode(sig))
    }

    /// Sign an unsigned transaction (Bitcoin-format hex): sets each input's
    /// `script_sig` to the canonical length-prefixed `sig‖pubkey`
    /// (`Transaction::build_script_sig`) so it is byte-compatible with the node's
    /// signer + consensus verification (`parse_script_sig`). Returns the signed
    /// tx hex, ready to broadcast via `sendrawtransaction`.
    pub fn sign_tx_hex(&self, unsigned_tx_hex: &str) -> Result<String, String> {
        use bloch_crypto::core::Transaction;
        let bytes = hex::decode(unsigned_tx_hex).map_err(|e| format!("bad tx hex: {}", e))?;
        let mut tx =
            Transaction::from_stratum_bytes(&bytes).map_err(|e| format!("parse tx: {}", e))?;
        // Roadmap #8: fold the wallet's network chain-id into the sighash so the
        // mobile signer is byte-identical to the node validator for this network
        // (a testnet wallet signs under the Testnet domain; the node rejects it
        // otherwise). Must match core::node_chain_id() on the validating node.
        let chain_id = if self.testnet {
            bloch_crypto::core::ChainId::Testnet
        } else {
            bloch_crypto::core::ChainId::Mainnet
        };
        for i in 0..tx.inputs.len() {
            let sighash = tx.sighash(i, chain_id);
            let sig = crypto::sign(&self.secret_key, &sighash).map_err(|e| e.to_string())?;
            tx.inputs[i].script_sig = Transaction::build_script_sig(&sig, &self.public_key);
        }
        Ok(hex::encode(tx.to_stratum_bytes(true)))
    }
}

impl Drop for WalletCore {
    /// Wipe secret material from memory on drop (defense in depth). The native
    /// side keeps the durable secret in secure hardware (StrongBox / Secure
    /// Enclave); this clears the transient in-RAM copy.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret_key.zeroize();
        self.seed.zeroize();
    }
}

// ── JSON-RPC helpers (pure; native side performs the HTTP POST) ───────────────

/// Build a JSON-RPC request body for the node's HTTP RPC.
pub fn rpc_request(method: &str, params: serde_json::Value) -> String {
    json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string()
}

pub fn getbalance_request(address: &str) -> String { rpc_request("getbalance", json!([address])) }
pub fn getblockcount_request() -> String { rpc_request("getblockcount", json!([])) }
pub fn getattestation_request(nonce: &str) -> String { rpc_request("getattestation", json!([nonce])) }

/// Extract a plain `result` integer (getblockcount / a balance in sats).
pub fn parse_u64_result(response_json: &str) -> Result<u64, String> {
    let v: serde_json::Value = serde_json::from_str(response_json).map_err(|e| e.to_string())?;
    if let Some(e) = v.get("error").filter(|e| !e.is_null()) {
        return Err(format!("rpc error: {}", e));
    }
    v.get("result")
        .and_then(|r| r.as_u64().or_else(|| r.get("balance").and_then(|b| b.as_u64())))
        .ok_or_else(|| "no u64 result".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Removed the PRE-FORK `address_matches_node_for_documented_seed` test: it
    // pinned the documented-dev-seed address from bloch-crypto branch="main",
    // BEFORE Dev-A's suite-ID envelope. Post-rev-pin the enveloped pk changes
    // that derived address; per that test's own note the authoritative
    // mobile<->node byte-identity anchor is now the golden below
    // (`golden_byte_identity_asserts_equal_to_dev_a_canonical_tuple`), which
    // ASSERTS-EQUAL to Dev-A's PUBLISHED canonical tuple and passes. Removed in
    // favor of the published-tuple anchor — NOT silently re-blessed.

    /// Post-fork mobile golden byte-identity anchor — ASSERT-EQUAL to Dev-A's
    /// FROZEN canonical tuple (R6/R8), never independently recomputed.
    ///
    /// Dev-A's canonical tuple (frozen handoff): under suite 0x0001 the address
    /// hashes the ENVELOPED pk, so for `GOLDEN_SEED = [0x11; 32]`,
    /// `generate_keypair_from_seed` + `address_from_pubkey` yields
    ///   mainnet: bloch1q7b003a342f1529f4943e52181c661b0e34c96d02b71f8b78
    ///   testnet: bloch1t7b003a342f1529f4943e52181c661b0e34c96d02b71f8b78
    /// `WalletCore::from_seed_bytes` performs exactly that derivation, so once
    /// this crate's `bloch-crypto` git-dep is re-pinned to Dev-A's merged SHA
    /// this test must go green with NO literal change.
    ///
    /// LANDED + GREEN: the rev-pin is applied (Cargo.toml `rev = dd8df352…`,
    /// grep-confirmed identical across every coordinated bloch-protocol
    /// Cargo.toml), so this is now a LIVE assert-equal (never `#[ignore]`) and
    /// passes under `cargo test`. It stays an assert-equal, NOT a re-bless: the
    /// literals are Dev-A's published values, copied from the frozen handoff,
    /// not recomputed here — if the enveloped derivation ever drifts, this test
    /// fails loudly rather than being silently updated.
    #[test]
    fn golden_byte_identity_asserts_equal_to_dev_a_canonical_tuple() {
        const GOLDEN_SEED: [u8; 32] = [0x11; 32];
        // mainnet (testnet = false)
        assert_eq!(
            WalletCore::from_seed_bytes(&GOLDEN_SEED, false).unwrap().address(),
            "bloch1q7b003a342f1529f4943e52181c661b0e34c96d02b71f8b78",
            "mobile golden (mainnet) must assert-equal to Dev-A's canonical address"
        );
        // testnet (testnet = true)
        assert_eq!(
            WalletCore::from_seed_bytes(&GOLDEN_SEED, true).unwrap().address(),
            "bloch1t7b003a342f1529f4943e52181c661b0e34c96d02b71f8b78",
            "mobile golden (testnet) must assert-equal to Dev-A's canonical address"
        );
    }

    #[test]
    fn diversified_address_rotation() {
        let w = WalletCore::from_seed_bytes(b"a-seed-at-least-32-bytes-long-xxxx", true).unwrap();
        // Index 0 is the base address (unchanged → golden test still holds).
        assert_eq!(w.address_at(0).unwrap(), w.address());
        // 1, 2, … are distinct, unlinkable, and valid.
        let a1 = w.address_at(1).unwrap();
        let a2 = w.address_at(2).unwrap();
        assert_ne!(a1, w.address());
        assert_ne!(a1, a2);
        assert!(a1.starts_with("bloch1t"));
        // Deterministic — recoverable from the seed.
        assert_eq!(a1, w.address_at(1).unwrap());
        // The diversified key can sign (spendable from a rotated address).
        assert!(w.sign_at(1, "deadbeef").is_ok());
    }

    #[test]
    fn sign_tx_hex_produces_consensus_verifiable_signature() {
        use bloch_crypto::core::{Transaction, TxInput, TxOutput};
        let w = WalletCore::from_seed_bytes(b"a-seed-at-least-32-bytes-long-xxxx", true).unwrap();
        let unsigned = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [3u8; 32], prev_index: 1, script_sig: vec![], sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOutput { value: 500, script_pubkey: vec![9u8; 20] }],
            locktime: 0,
        };
        let unsigned_hex = hex::encode(unsigned.to_stratum_bytes(true));
        let signed_hex = w.sign_tx_hex(&unsigned_hex).unwrap();
        let signed = Transaction::from_stratum_bytes(&hex::decode(signed_hex).unwrap()).unwrap();
        // The consensus verifier extracts (sig, pk) with parse_script_sig; it must verify.
        let (sig, pk) = Transaction::parse_script_sig(&signed.inputs[0].script_sig)
            .expect("length-prefixed script_sig");
        // w is testnet (from_seed_bytes(.., true)) so sign_tx_hex used the Testnet
        // domain — verify against the same chain-id.
        assert!(bloch_crypto::crypto::verify(&pk, &signed.sighash(0, bloch_crypto::core::ChainId::Testnet), &sig));
    }

    #[test]
    fn mnemonic_roundtrip_is_deterministic() {
        let (_w, phrase) = WalletCore::generate(false).unwrap();
        let a = WalletCore::from_mnemonic(&phrase, false).unwrap().address();
        let b = WalletCore::from_mnemonic(&phrase, false).unwrap().address();
        assert_eq!(a, b);
        assert!(a.starts_with("bloch1q"));
    }

    #[test]
    fn sign_produces_verifiable_hybrid_signature() {
        let w = WalletCore::from_seed_bytes(&[7u8; 32], false).unwrap();
        let msg_hex = hex::encode(b"mobile-sign-test");
        let sig_hex = w.sign_hex(&msg_hex).unwrap();
        let sig = hex::decode(&sig_hex).unwrap();
        assert!(bloch_crypto::crypto::verify(&w.public_key, b"mobile-sign-test", &sig));
    }

    #[test]
    fn rpc_request_shape() {
        let r = getattestation_request("nonce123");
        assert!(r.contains("\"method\":\"getattestation\""));
        assert!(r.contains("nonce123"));
        assert_eq!(parse_u64_result("{\"result\":42}").unwrap(), 42);
        assert!(parse_u64_result("{\"error\":\"boom\"}").is_err());
    }
}
