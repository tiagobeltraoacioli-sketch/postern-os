//! Wallet product — a thin UniFFI wrapper over `bloch_mobile::WalletCore`.
//!
//! Reuses bloch-mobile's public engine verbatim (no crypto reimplemented). The
//! wallet is held by value so `WalletCore`'s zeroizing `Drop` still runs when
//! the foreign object is released.

use crate::{lock_recover, PosternError};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// A light wallet: hybrid Falcon‖ML-DSA keypair + diversified addresses.
#[derive(uniffi::Object)]
pub struct Wallet {
    inner: bloch_mobile::WalletCore,
}

#[uniffi::export]
impl Wallet {
    /// Restore a wallet from a BIP39 mnemonic phrase.
    ///
    /// SECURITY: `phrase` is the wallet's only backup — never log it. The
    /// Rust-side copy is wiped before this returns; the foreign-side string is
    /// GC-managed and cannot be wiped, so drop app references to it promptly.
    #[uniffi::constructor]
    pub fn from_mnemonic(phrase: String, testnet: bool) -> Result<Arc<Wallet>, PosternError> {
        // Wrap the FFI copy so the Rust-side buffer is zeroized on drop.
        let phrase = Zeroizing::new(phrase);
        let inner = bloch_mobile::WalletCore::from_mnemonic(&phrase, testnet)
            .map_err(PosternError::from)?;
        Ok(Arc::new(Wallet { inner }))
    }

    /// The base (index 0) receiving address.
    pub fn address(&self) -> String {
        self.inner.address()
    }

    /// A diversified (unlinkable) receiving address for `index`.
    pub fn address_at(&self, index: u32) -> Result<String, PosternError> {
        self.inner.address_at(index).map_err(PosternError::from)
    }

    /// Sign with the diversified keypair for `index`.
    pub fn sign_at(&self, index: u32, message_hex: String) -> Result<String, PosternError> {
        self.inner.sign_at(index, &message_hex).map_err(PosternError::from)
    }

    /// The wallet's hybrid public key, hex-encoded.
    pub fn public_key_hex(&self) -> String {
        self.inner.public_key_hex()
    }

    /// Sign an arbitrary message (hex in → hybrid signature hex out).
    pub fn sign_hex(&self, message_hex: String) -> Result<String, PosternError> {
        self.inner.sign_hex(&message_hex).map_err(PosternError::from)
    }

    /// Sign an unsigned transaction (Bitcoin-format hex) → signed tx hex.
    pub fn sign_tx_hex(&self, unsigned_tx_hex: String) -> Result<String, PosternError> {
        self.inner.sign_tx_hex(&unsigned_tx_hex).map_err(PosternError::from)
    }
}

/// A freshly generated wallet behind an OPAQUE handle.
///
/// This is deliberately a UniFFI *object*, not a Record: Records lower into
/// Kotlin `data class` / Swift `struct` values whose auto-generated
/// `toString()`/`description` would print every field — including the BIP39
/// mnemonic, the wallet's ONLY backup — into logs, crash breadcrumbs and
/// debugger watches. As an object, stringifying the handle prints nothing; the
/// mnemonic crosses the boundary only on an explicit, ONE-SHOT
/// [`NewWallet::reveal_mnemonic`] call.
#[derive(uniffi::Object)]
pub struct NewWallet {
    wallet: Arc<Wallet>,
    /// The backup phrase, held zeroizing and consumed by the first reveal.
    mnemonic: Mutex<Option<Zeroizing<String>>>,
}

#[uniffi::export]
impl NewWallet {
    /// The live, ready-to-use wallet handle (no mnemonic round-trip needed).
    pub fn wallet(&self) -> Arc<Wallet> {
        self.wallet.clone()
    }

    /// Base (index 0) receiving address.
    pub fn address(&self) -> String {
        self.wallet.address()
    }

    /// Hybrid public key, hex-encoded.
    pub fn public_key_hex(&self) -> String {
        self.wallet.public_key_hex()
    }

    /// Whether the one-shot mnemonic is still available to reveal.
    pub fn mnemonic_available(&self) -> bool {
        lock_recover(&self.mnemonic).is_some()
    }

    /// ONE-SHOT: return the BIP39 backup phrase and wipe the Rust-side copy.
    ///
    /// The phrase is the ONLY backup — display it once for the user to record,
    /// then drop every reference. A second call returns an error. SECURITY:
    /// never log the returned string; the foreign-side copy is GC-managed and
    /// cannot be zeroized, so keep its lifetime as short as possible.
    pub fn reveal_mnemonic(&self) -> Result<String, PosternError> {
        lock_recover(&self.mnemonic)
            .take()
            // Copy out of the zeroizing wrapper; the wrapper wipes its buffer
            // on drop, so no un-scrubbed Rust-side copy remains.
            .map(|z| z.as_str().to_owned())
            .ok_or_else(|| PosternError::from("mnemonic already revealed (one-shot)"))
    }
}

/// Generate a new random wallet. The mnemonic never crosses the FFI as a
/// printable field — retrieve it exactly once via [`NewWallet::reveal_mnemonic`].
#[uniffi::export]
pub fn generate_wallet(testnet: bool) -> Result<Arc<NewWallet>, PosternError> {
    let (w, mnemonic) = bloch_mobile::WalletCore::generate(testnet).map_err(PosternError::from)?;
    Ok(Arc::new(NewWallet {
        wallet: Arc::new(Wallet { inner: w }),
        mnemonic: Mutex::new(Some(Zeroizing::new(mnemonic))),
    }))
}

// ── JSON-RPC helpers (pure; native side performs the HTTP POST) ───────────────

/// Build a `getbalance` JSON-RPC request body for `address`.
#[uniffi::export]
pub fn rpc_getbalance(address: String) -> String {
    bloch_mobile::getbalance_request(&address)
}

/// Build a `getblockcount` JSON-RPC request body.
#[uniffi::export]
pub fn rpc_getblockcount() -> String {
    bloch_mobile::getblockcount_request()
}

/// Build a `getattestation` JSON-RPC request body for `nonce`.
#[uniffi::export]
pub fn rpc_getattestation(nonce: String) -> String {
    bloch_mobile::getattestation_request(&nonce)
}

/// Build an arbitrary JSON-RPC request body. `params_json` is the raw JSON
/// array/object for the method's params.
#[uniffi::export]
pub fn rpc_request(method: String, params_json: String) -> Result<String, PosternError> {
    let params: serde_json::Value =
        serde_json::from_str(&params_json).map_err(|e| PosternError::from(e.to_string()))?;
    Ok(bloch_mobile::rpc_request(&method, params))
}

/// Parse a plain `result` integer (getblockcount / a balance in sats) from a
/// JSON-RPC response body.
#[uniffi::export]
pub fn parse_u64_result(response_json: String) -> Result<u64, PosternError> {
    bloch_mobile::parse_u64_result(&response_json).map_err(PosternError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mnemonic_is_one_shot_and_wallet_restores() {
        let nw = generate_wallet(true).unwrap();
        let address = nw.address();
        assert!(nw.mnemonic_available());

        // First reveal succeeds; the handle itself exposes no printable secret.
        let phrase = nw.reveal_mnemonic().unwrap();
        assert!(!phrase.is_empty());
        assert!(!nw.mnemonic_available());

        // Second reveal is refused — the Rust-side copy is gone (zeroized).
        assert!(nw.reveal_mnemonic().is_err());

        // The live handle works without the mnemonic ever re-crossing the FFI.
        assert_eq!(nw.wallet().address(), address);

        // And the revealed phrase restores the same wallet.
        let restored = Wallet::from_mnemonic(phrase, true).unwrap();
        assert_eq!(restored.address(), address);
    }
}
