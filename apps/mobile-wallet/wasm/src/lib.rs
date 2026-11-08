//! Postern Wallet — mobile · WASM crypto core
//! ============================================
//!
//! A thin WebAssembly wrapper over `bloch-crypto` — the SAME crate the Bloch
//! node and `bloch-cli` use. Nothing here re-implements the cryptography: keygen,
//! the hybrid Falcon‖ML-DSA signature, address derivation and transaction
//! construction all call straight into `bloch-crypto`, so a signature this module
//! produces is byte-for-byte what the node verifies, and an address it derives is
//! byte-identical to the one `bloch-cli` shows.
//!
//! ABI: three C exports — `bw_alloc(len) -> ptr`, `bw_free(ptr, len)`, and
//! `bw_call(method_ptr,method_len, args_ptr,args_len) -> result_ptr`. `bw_call`
//! takes a method name + a JSON args object and returns a buffer
//! `[ok:u8][len:u32-le][utf8 json]`. The JS side (wallet-wasm.js) marshals
//! strings across this boundary; we avoid wasm-bindgen because it does not
//! support the wasm32-wasip1 target this crypto requires.
//!
//! HONESTY: unaudited beta. A browser keystore is NOT a hardware secure enclave —
//! decrypted key material is briefly present in WASM/JS memory while signing. The
//! coin BLOCH carries no value claim.

use std::alloc::{alloc, dealloc, Layout};
use zeroize::Zeroize;

use bloch_crypto::address::Address;
use bloch_crypto::core::TxOutput;
use bloch_crypto::crypto;
use bloch_crypto::hd_wallet::HdWalletFile;
use bloch_crypto::wallet::{seed::SeedPhrase, EncryptedKeystore, Keypair, TxBuilder};

use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Key, Nonce};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha3::{Digest, Sha3_256};

// ════════════════════════════════════════════════════════════════════════════
// C-ABI marshalling layer
// ════════════════════════════════════════════════════════════════════════════

/// Allocate `len` bytes for the JS side to write an argument buffer into.
#[no_mangle]
pub extern "C" fn bw_alloc(len: usize) -> *mut u8 {
    if len == 0 {
        return std::ptr::null_mut();
    }
    // 1-byte alignment is fine — these are opaque byte buffers.
    unsafe { alloc(Layout::from_size_align_unchecked(len, 1)) }
}

/// Free a buffer previously returned by `bw_alloc` or `bw_call`.
#[no_mangle]
pub extern "C" fn bw_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        unsafe { dealloc(ptr, Layout::from_size_align_unchecked(len, 1)) }
    }
}

/// Pack a result into `[ok:u8][len:u32 LE][bytes]`. The JS caller reads `len`,
/// copies `bytes`, then frees `5 + len`.
fn pack(ok: bool, s: &str) -> *mut u8 {
    let bytes = s.as_bytes();
    let total = 5 + bytes.len();
    let ptr = bw_alloc(total);
    unsafe {
        *ptr = ok as u8;
        let len = (bytes.len() as u32).to_le_bytes();
        std::ptr::copy_nonoverlapping(len.as_ptr(), ptr.add(1), 4);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.add(5), bytes.len());
    }
    ptr
}

/// The single entry point. `method` selects the operation; `args` is a JSON
/// object. Returns a packed result buffer (see `pack`).
#[no_mangle]
pub extern "C" fn bw_call(
    method_ptr: *const u8,
    method_len: usize,
    args_ptr: *const u8,
    args_len: usize,
) -> *mut u8 {
    let method = unsafe { slice_str(method_ptr, method_len) };
    let args = unsafe { slice_str(args_ptr, args_len) };
    let out = std::panic::catch_unwind(|| dispatch(&method, &args))
        .unwrap_or_else(|_| Err("internal panic in wallet core".into()));
    match out {
        Ok(s) => pack(true, &s),
        Err(e) => pack(false, &e),
    }
}

unsafe fn slice_str(ptr: *const u8, len: usize) -> String {
    if ptr.is_null() || len == 0 {
        return String::new();
    }
    String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).into_owned()
}

// ════════════════════════════════════════════════════════════════════════════
// Dispatch
// ════════════════════════════════════════════════════════════════════════════

type R = Result<String, String>;

fn dispatch(method: &str, args: &str) -> R {
    let v: Value = if args.trim().is_empty() {
        Value::Object(Default::default())
    } else {
        serde_json::from_str(args).map_err(|e| e.to_string())?
    };
    match method {
        "core_version" => Ok(json_str("version", &core_version())),
        "new_mnemonic" => new_mnemonic(&v),
        "normalize_mnemonic" => normalize_mnemonic(&v),
        "wallet_from_mnemonic" => wallet_from_mnemonic(&v),
        "address_from_pubkey" => address_from_pubkey(&v),
        "debug_seed_mldsa_pk_hash" => debug_seed_mldsa_pk_hash(&v),
        "build_and_sign_tx" => build_and_sign_tx(&v),
        "build_and_sign_tx_from_mnemonic" => build_and_sign_tx_from_mnemonic(&v),
        "import_simple_wallet" => import_simple_wallet(&v),
        "import_hd_wallet" => import_hd_wallet(&v),
        "keystore_seal" => keystore_seal(&v),
        "keystore_open" => keystore_open(&v),
        other => Err(format!("unknown method: {other}")),
    }
}

fn core_version() -> String {
    format!("bloch-wallet-wasm {} · hybrid ML-DSA-65‖Falcon-1024", env!("CARGO_PKG_VERSION"))
}

// ── small helpers ─────────────────────────────────────────────────────────────
fn s(v: &Value, k: &str) -> Result<String, String> {
    v.get(k)
        .and_then(|x| x.as_str())
        .map(|x| x.to_string())
        .ok_or_else(|| format!("missing string field '{k}'"))
}
fn s_opt(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}
fn b(v: &Value, k: &str) -> bool {
    v.get(k).and_then(|x| x.as_bool()).unwrap_or(false)
}
fn json_str(k: &str, val: &str) -> String {
    serde_json::to_string(&serde_json::json!({ k: val })).unwrap()
}
fn to_json<T: Serialize>(v: &T) -> R {
    serde_json::to_string(v).map_err(|e| e.to_string())
}

// ════════════════════════════════════════════════════════════════════════════
// Mnemonic + deterministic wallet (Create-new flow)
// ════════════════════════════════════════════════════════════════════════════

fn new_mnemonic(v: &Value) -> R {
    let words = v.get("words").and_then(|x| x.as_u64()).unwrap_or(24);
    let entropy_len = match words {
        12 => 16usize,
        24 => 32usize,
        _ => return Err("word count must be 12 or 24".into()),
    };
    let mut entropy = vec![0u8; entropy_len];
    getrandom::fill(&mut entropy).map_err(|e| e.to_string())?;
    let m = bip39::Mnemonic::from_entropy(&entropy).map_err(|e| e.to_string())?;
    entropy.zeroize();
    Ok(json_str("mnemonic", &m.to_string()))
}

fn normalize_mnemonic(v: &Value) -> R {
    let m = SeedPhrase::parse(&s(v, "mnemonic")?).map_err(|e| e.to_string())?;
    Ok(json_str("mnemonic", &m.words().join(" ")))
}

#[derive(Serialize)]
struct WalletView {
    address: String,
    public_key_hex: String,
    network: String,
}

fn wallet_from_mnemonic(v: &Value) -> R {
    let testnet = b(v, "testnet");
    let kp = keypair_from_mnemonic(&s(v, "mnemonic")?, testnet)?;
    to_json(&WalletView {
        address: kp.address.clone(),
        public_key_hex: hex::encode(&kp.public_key),
        network: net_name(testnet),
    })
}

/// Byte-identical to `bloch_crypto::wallet::Wallet::from_seed`.
fn keypair_from_mnemonic(mnemonic: &str, testnet: bool) -> Result<Keypair, String> {
    let seed = SeedPhrase::parse(mnemonic).map_err(|e| e.to_string())?;
    let seed_bytes = seed.to_seed_bytes();
    let (public_key, private_key) =
        crypto::generate_keypair_from_seed(&seed_bytes[..32]).map_err(|e| e.to_string())?;
    let address = crypto::address_from_pubkey(&public_key, testnet);
    Ok(Keypair { private_key, public_key, address })
}

fn address_from_pubkey(v: &Value) -> R {
    let pk = hex::decode(s(v, "pubkey_hex")?.trim()).map_err(|e| e.to_string())?;
    Ok(json_str("address", &crypto::address_from_pubkey(&pk, b(v, "testnet"))))
}

/// Golden-vector probe: SHA3-256 of the ML-DSA-65 public-key half for a 32-byte
/// seed. The node pins seed=0x11*32 to
/// bb34618ab597cc394fcfa9c9c5791d4767baacce3648285e8069742a55e2de37 — a
/// byte-identical check that WASM keygen == node keygen.
fn debug_seed_mldsa_pk_hash(v: &Value) -> R {
    let seed = hex::decode(s(v, "seed_hex")?.trim()).map_err(|e| e.to_string())?;
    if seed.len() < 32 {
        return Err("seed must be >= 32 bytes".into());
    }
    let (pk, _sk) = crypto::generate_keypair_from_seed(&seed[..32]).map_err(|e| e.to_string())?;
    const HDR: usize = 4;
    const MLDSA_PK: usize = 1952;
    if pk.len() < HDR + MLDSA_PK {
        return Err("unexpected pubkey length".into());
    }
    Ok(json_str("hash", &hex::encode(Sha3_256::digest(&pk[HDR..HDR + MLDSA_PK]))))
}

fn net_name(testnet: bool) -> String {
    if testnet { "testnet" } else { "mainnet" }.to_string()
}

// ════════════════════════════════════════════════════════════════════════════
// Transaction build + real hybrid signature (Send flow)
// ════════════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct UtxoIn {
    txid: String,
    index: u32,
    value: u64,
}

#[derive(Serialize)]
struct SignedTxView {
    raw_hex: String,
    txid_hex: String,
    input_count: usize,
    output_count: usize,
    sig_len: usize,
}

fn build_and_sign_tx(v: &Value) -> R {
    let private_key = hex::decode(s(v, "secret_hex")?.trim()).map_err(|e| e.to_string())?;
    let public_key = hex::decode(s(v, "public_hex")?.trim()).map_err(|e| e.to_string())?;
    let kp = Keypair { private_key, public_key, address: s(v, "address")? };
    sign_with_keypair(&kp, v)
}

fn build_and_sign_tx_from_mnemonic(v: &Value) -> R {
    let kp = keypair_from_mnemonic(&s(v, "mnemonic")?, b(v, "testnet"))?;
    sign_with_keypair(&kp, v)
}

fn sign_with_keypair(kp: &Keypair, v: &Value) -> R {
    let amount: u64 = s(v, "amount_sats")?.trim().parse().map_err(|_| "bad amount_sats")?;
    let fee: u64 = s(v, "fee_sats")?.trim().parse().map_err(|_| "bad fee_sats")?;

    let dest = Address::parse(s(v, "to")?.trim()).map_err(|e| e.to_string())?;
    let from = Address::parse(&kp.address).map_err(|e| e.to_string())?;
    if dest.network() != from.network() {
        return Err("destination is on the other network — refusing cross-network send".into());
    }
    let to_hex = hex::encode(dest.hash());

    let utxos: Vec<UtxoIn> = serde_json::from_value(
        v.get("utxos").cloned().unwrap_or(Value::Array(vec![])),
    )
    .map_err(|e| e.to_string())?;
    if utxos.is_empty() {
        return Err("no UTXOs to spend".into());
    }
    let mut available: Vec<(Vec<u8>, u32, TxOutput)> = Vec::with_capacity(utxos.len());
    for u in &utxos {
        let txid = hex::decode(u.txid.trim()).map_err(|e| e.to_string())?;
        if txid.len() != 32 {
            return Err("utxo txid must be 32 bytes".into());
        }
        available.push((txid, u.index, TxOutput { value: u.value, script_pubkey: vec![] }));
    }

    let tx = TxBuilder::build(kp, &available, &to_hex, amount, fee)?;
    let raw = tx.to_stratum_bytes(true);
    to_json(&SignedTxView {
        raw_hex: hex::encode(&raw),
        txid_hex: hex::encode(tx.txid()),
        input_count: tx.inputs.len(),
        output_count: tx.outputs.len(),
        sig_len: tx.inputs.first().map(|i| i.script_sig.len()).unwrap_or(0),
    })
}

// ════════════════════════════════════════════════════════════════════════════
// Import: bloch-cli wallet JSON (simple keypair / founder.json, and HD BIP39)
// ════════════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct KeypairPayload {
    private_key_hex: String,
    public_key_hex: String,
}
#[derive(Deserialize)]
struct MnemonicPayload {
    mnemonic: String,
}

#[derive(Serialize)]
struct ImportedKey {
    index: u32,
    label: String,
    address: String,
    public_key_hex: String,
    private_key_hex: String,
}
#[derive(Serialize)]
struct ImportView {
    kind: String,
    network: String,
    mnemonic: Option<String>,
    keys: Vec<ImportedKey>,
}

/// Argon2id with the EXACT bloch-cli parameters (m=262144 KiB = 256 MiB, t=4,
/// p=4, 32-byte out). Must match `bloch_crypto`'s `derive_key` /
/// `derive_master_key` so a wallet file decrypts.
fn argon2_cli_key(input: &[u8], salt: &[u8]) -> Result<[u8; 32], String> {
    let params = Params::new(262144, 4, 4, Some(32)).map_err(|e| e.to_string())?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    a.hash_password_into(input, salt, &mut key).map_err(|e| e.to_string())?;
    Ok(key)
}

fn aes_gcm_open(key: &[u8], nonce_b64: &str, ct_b64: &str) -> Result<Vec<u8>, String> {
    let nonce = B64.decode(nonce_b64).map_err(|e| e.to_string())?;
    let ct = B64.decode(ct_b64).map_err(|e| e.to_string())?;
    if nonce.len() != 12 {
        return Err("bad nonce length".into());
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(&nonce), ct.as_ref())
        .map_err(|_| "decrypt failed — wrong password or corrupt file".to_string())
}

fn import_simple_wallet(v: &Value) -> R {
    let ks: EncryptedKeystore =
        serde_json::from_str(&s(v, "json")?).map_err(|e| e.to_string())?;
    if ks.version != 2 {
        return Err("unsupported keystore version (need v2)".into());
    }
    let salt = B64.decode(&ks.crypto.kdf_params.salt).map_err(|e| e.to_string())?;
    let mut key = argon2_cli_key(s(v, "password")?.as_bytes(), &salt)?;
    let plain = aes_gcm_open(&key, &ks.crypto.nonce, &ks.crypto.ciphertext);
    key.zeroize();
    let plain = plain?;
    let payload: KeypairPayload = serde_json::from_slice(&plain).map_err(|e| e.to_string())?;

    let public_key = hex::decode(&payload.public_key_hex).map_err(|e| e.to_string())?;
    let testnet = ks.address.starts_with("bloch1t");
    let derived = crypto::address_from_pubkey(&public_key, testnet);
    if derived != ks.address {
        return Err("address mismatch — keystore may be tampered".into());
    }
    to_json(&ImportView {
        kind: "simple".into(),
        network: net_name(testnet),
        mnemonic: None,
        keys: vec![ImportedKey {
            index: 0,
            label: "imported".into(),
            address: ks.address.clone(),
            public_key_hex: payload.public_key_hex.clone(),
            private_key_hex: payload.private_key_hex.clone(),
        }],
    })
}

fn import_hd_wallet(v: &Value) -> R {
    let wf: HdWalletFile = serde_json::from_str(&s(v, "json")?).map_err(|e| e.to_string())?;
    if wf.format != "hd-wallet-v1" {
        return Err("unsupported wallet format".into());
    }
    let m = bip39::Mnemonic::parse(s(v, "mnemonic")?.trim()).map_err(|e| e.to_string())?;
    let mnemonic_canon = m.to_string();
    let passphrase = s_opt(v, "passphrase");
    let password = s(v, "password")?;

    // master_key = Argon2id(mnemonic \0 passphrase \0 password, salt)
    let mut combined =
        Vec::with_capacity(mnemonic_canon.len() + passphrase.len() + password.len() + 2);
    combined.extend_from_slice(mnemonic_canon.as_bytes());
    combined.push(0);
    combined.extend_from_slice(passphrase.as_bytes());
    combined.push(0);
    combined.extend_from_slice(password.as_bytes());

    let salt = if wf.version >= 2 {
        let mut h = Sha3_256::new();
        h.update(b"bloch-sis/hd-wallet/salt/v2");
        h.update(mnemonic_canon.as_bytes());
        h.finalize().to_vec()
    } else {
        Sha3_256::digest(b"bloch-layer-hd-wallet-v1").to_vec()
    };
    let mut master = argon2_cli_key(&combined, &salt)?;
    combined.zeroize();

    let m_plain = aes_gcm_open(&master, &wf.mnemonic_crypto.nonce, &wf.mnemonic_crypto.ciphertext);
    let m_plain = match m_plain {
        Ok(p) => p,
        Err(e) => {
            master.zeroize();
            return Err(e);
        }
    };
    let mp: MnemonicPayload = serde_json::from_slice(&m_plain).map_err(|e| e.to_string())?;
    if mp.mnemonic != mnemonic_canon {
        master.zeroize();
        return Err("mnemonic mismatch — wrong password/passphrase/mnemonic".into());
    }

    let testnet = wf.network == "testnet";
    let mut keys = Vec::with_capacity(wf.addresses.len());
    for a in &wf.addresses {
        let plain =
            match aes_gcm_open(&master, &a.keypair_crypto.nonce, &a.keypair_crypto.ciphertext) {
                Ok(p) => p,
                Err(e) => {
                    master.zeroize();
                    return Err(e);
                }
            };
        let payload: KeypairPayload = serde_json::from_slice(&plain).map_err(|e| e.to_string())?;
        let public_key = hex::decode(&payload.public_key_hex).map_err(|e| e.to_string())?;
        let derived = crypto::address_from_pubkey(&public_key, testnet);
        if derived != a.address {
            master.zeroize();
            return Err("address mismatch in HD wallet — tampered file".into());
        }
        keys.push(ImportedKey {
            index: a.index,
            label: a.label.clone(),
            address: a.address.clone(),
            public_key_hex: payload.public_key_hex.clone(),
            private_key_hex: payload.private_key_hex.clone(),
        });
    }
    master.zeroize();

    to_json(&ImportView {
        kind: "hd".into(),
        network: wf.network.clone(),
        mnemonic: Some(mnemonic_canon),
        keys,
    })
}

// ════════════════════════════════════════════════════════════════════════════
// App keystore: seal/open a secret payload for IndexedDB (Argon2id + XChaCha20-
// Poly1305). This is the keystore the wallet writes for ITSELF (not a CLI file).
// XChaCha20-Poly1305 — NOT AES-GCM — is deliberate: the 192-bit random nonce
// removes the GCM nonce-reuse failure mode, and ChaCha is constant-time in pure
// software/WASM (there is no AES-NI in wasm). AES-256-GCM stays ONLY on the
// bloch-cli interop path (import_* above), where the on-disk format is fixed.
// Every seal draws a FRESH random salt (→ fresh Argon2id key) and FRESH nonce.
// ════════════════════════════════════════════════════════════════════════════

// Lighter than the CLI's 256 MiB so unlock is snappy in a browser, still
// Argon2id: 64 MiB, 3 passes, 1 lane. Protects the at-rest secret with a
// passphrase; NOT a hardware enclave.
const KS_M_COST: u32 = 65536;
const KS_T_COST: u32 = 3;
const KS_P_COST: u32 = 1;

#[derive(Serialize, Deserialize)]
struct KeystoreBlob {
    v: u32,
    kdf: String,
    #[serde(default)]
    cipher: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt_b64: String,
    nonce_b64: String,
    ct_b64: String,
}

/// XChaCha20-Poly1305 open (192-bit nonce). Used by the app keystore only.
fn xchacha_open(key: &[u8], nonce_b64: &str, ct_b64: &str) -> Result<Vec<u8>, String> {
    let nonce = B64.decode(nonce_b64).map_err(|e| e.to_string())?;
    let ct = B64.decode(ct_b64).map_err(|e| e.to_string())?;
    if nonce.len() != 24 {
        return Err("bad nonce length".into());
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|e| e.to_string())?;
    cipher
        .decrypt(XNonce::from_slice(&nonce), ct.as_ref())
        .map_err(|_| "decrypt failed — wrong password or corrupt keystore".to_string())
}

fn keystore_seal(v: &Value) -> R {
    let plaintext = s(v, "plaintext")?;
    let passphrase = s(v, "passphrase")?;
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24]; // XChaCha20 uses a 192-bit (24-byte) nonce
    getrandom::fill(&mut salt).map_err(|e| e.to_string())?;
    getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
    let params = Params::new(KS_M_COST, KS_T_COST, KS_P_COST, Some(32)).map_err(|e| e.to_string())?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    a.hash_password_into(passphrase.as_bytes(), &salt, &mut key).map_err(|e| e.to_string())?;
    let cipher = match XChaCha20Poly1305::new_from_slice(&key) {
        Ok(c) => c,
        Err(e) => {
            key.zeroize();
            return Err(e.to_string());
        }
    };
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext.as_bytes())
        .map_err(|_| "encrypt failed".to_string());
    key.zeroize();
    let ct = ct?;
    to_json(&KeystoreBlob {
        v: 1,
        kdf: "argon2id".into(),
        cipher: "xchacha20poly1305".into(),
        m_cost: KS_M_COST,
        t_cost: KS_T_COST,
        p_cost: KS_P_COST,
        salt_b64: B64.encode(salt),
        nonce_b64: B64.encode(nonce),
        ct_b64: B64.encode(&ct),
    })
}

fn keystore_open(v: &Value) -> R {
    let blob: KeystoreBlob = serde_json::from_str(&s(v, "blob")?).map_err(|e| e.to_string())?;
    let passphrase = s(v, "passphrase")?;
    // The app keystore is XChaCha20-Poly1305. Reject anything else rather than
    // silently trying (an AES-GCM CLI file is never opened through this path).
    if !blob.cipher.is_empty() && blob.cipher != "xchacha20poly1305" {
        return Err(format!("unsupported app-keystore cipher '{}'", blob.cipher));
    }
    let salt = B64.decode(&blob.salt_b64).map_err(|e| e.to_string())?;
    let params =
        Params::new(blob.m_cost, blob.t_cost, blob.p_cost, Some(32)).map_err(|e| e.to_string())?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    a.hash_password_into(passphrase.as_bytes(), &salt, &mut key).map_err(|e| e.to_string())?;
    let plain = xchacha_open(&key, &blob.nonce_b64, &blob.ct_b64);
    key.zeroize();
    let plain = plain?;
    Ok(json_str("plaintext", &String::from_utf8(plain).map_err(|e| e.to_string())?))
}
