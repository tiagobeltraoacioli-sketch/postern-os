package labs.postern.wallet

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

// UniFFI-generated surface: the ONE unified Postern SDK facade
// (crates/postern-sdk → uniffi/postern_sdk/postern_sdk.kt). Migrated off the old
// per-wallet `uniffi.bloch_mobile` surface (Dev-F1 UniFFI convergence).
import uniffi.postern_sdk.NewWallet
import uniffi.postern_sdk.PosternException
import uniffi.postern_sdk.Wallet
import uniffi.postern_sdk.generateWallet

/** Immutable snapshot the Compose UI renders. */
data class WalletUiState(
    val address: String? = null,
    val publicKeyHex: String? = null,
    /** Shown exactly ONCE right after creation — the only backup. Never persisted. */
    val mnemonicToBackUp: String? = null,
    val balanceSats: ULong? = null,
    val chainHeight: ULong? = null,
    val busy: Boolean = false,
    val lastTxid: String? = null,
    val error: String? = null,
)

/**
 * Owns the live [Wallet] (UniFFI object) and drives it against the node RPC.
 *
 * The mnemonic is a one-shot backup: `generateWallet` returns it, the UI shows
 * it once, then it is dropped. Durable restore is via [restore] (from the
 * mnemonic the user wrote down), and at-rest protection of the reconstructed
 * secret is the job of [StrongBoxKey] (wrap key) — see mobile/README.md.
 */
class WalletViewModel(
    private val rpc: NodeRpc = NodeRpc(DEFAULT_NODE_ENDPOINT),
    private val testnet: Boolean = true,
) : ViewModel() {

    private val _state = MutableStateFlow(WalletUiState())
    val state: StateFlow<WalletUiState> = _state.asStateFlow()

    /** The in-memory wallet engine. Its secret material is zeroized on drop (Rust). */
    private var wallet: Wallet? = null

    /** Create a brand-new wallet; surfaces the mnemonic once for the user to back up. */
    fun createWallet() = launchGuarded {
        // SDK `NewWallet` is an opaque handle (not a Record): the mnemonic never
        // crosses as a printable field. Take the live wallet directly via
        // `wallet()` (no mnemonic round-trip) and reveal the backup ONCE.
        val fresh: NewWallet = generateWallet(testnet)
        wallet = fresh.wallet()
        val mnemonic = fresh.revealMnemonic()   // one-shot; wiped Rust-side after
        _state.update {
            it.copy(
                address = fresh.address(),
                publicKeyHex = fresh.publicKeyHex(),
                mnemonicToBackUp = mnemonic,
                balanceSats = null,
                lastTxid = null,
            )
        }
        refreshBalance()
    }

    /** Restore a wallet from a user-supplied BIP39 mnemonic. */
    fun restore(mnemonic: String) = launchGuarded {
        val w = Wallet.fromMnemonic(mnemonic.trim(), testnet)
        wallet = w
        _state.update {
            it.copy(
                address = w.address(),
                publicKeyHex = w.publicKeyHex(),
                mnemonicToBackUp = null,
                balanceSats = null,
                lastTxid = null,
            )
        }
        refreshBalance()
    }

    /** The user has recorded the mnemonic; clear it from UI state. */
    fun dismissMnemonicBackup() = _state.update { it.copy(mnemonicToBackUp = null) }

    /** Pull the current balance + chain height from the node. */
    fun refreshBalance() = launchGuarded {
        val address = wallet?.address() ?: return@launchGuarded
        val balance = rpc.getBalance(address)
        val height = runCatching { rpc.getBlockCount() }.getOrNull()
        _state.update { it.copy(balanceSats = balance, chainHeight = height) }
    }

    /**
     * Send stub: signs an unsigned transaction hex with the core's `signTxHex`
     * and broadcasts it. In a full build, the unsigned tx (inputs/outputs) is
     * assembled from UTXOs fetched over RPC; here we take the caller-provided
     * unsigned hex to keep the signing path honest (real `signTxHex` call).
     */
    fun signAndBroadcast(unsignedTxHex: String) = launchGuarded {
        val w = wallet ?: throw PosternException.Postern("no wallet loaded")
        val signedHex = w.signTxHex(unsignedTxHex)   // hybrid PQ signature, node-compatible
        val response = rpc.sendRawTransaction(signedHex)
        _state.update { it.copy(lastTxid = response) }
    }

    private fun launchGuarded(block: suspend () -> Unit) {
        viewModelScope.launch {
            _state.update { it.copy(busy = true, error = null) }
            try {
                block()
            } catch (e: PosternException) {
                _state.update { it.copy(error = e.message ?: "wallet error") }
            } catch (e: RpcException) {
                _state.update { it.copy(error = e.message ?: "node error") }
            } catch (e: Exception) {
                _state.update { it.copy(error = e.message ?: "unexpected error") }
            } finally {
                _state.update { it.copy(busy = false) }
            }
        }
    }

    companion object {
        // Point at a reachable node's JSON-RPC. Override in a real build (BuildConfig / settings).
        const val DEFAULT_NODE_ENDPOINT = "http://10.0.2.2:8332/"
    }
}
