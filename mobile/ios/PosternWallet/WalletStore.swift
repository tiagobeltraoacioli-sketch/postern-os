import Foundation

// UniFFI-generated Swift surface: the ONE unified Postern SDK facade
// (crates/postern-sdk → postern_sdk.swift). Migrated off the old per-wallet
// `bloch_mobile` module (Dev-F1 UniFFI convergence).
import postern_sdk

/// Observable wallet state driving the SwiftUI views.
///
/// Owns the live `Wallet` (UniFFI object) and drives it against the node RPC.
/// The mnemonic is a one-shot backup: `generateWallet` returns it, the UI shows
/// it once, then it is cleared. At-rest protection of the reconstructed secret
/// is the job of `SecureEnclaveKey` (wrap key) — see mobile/README.md.
@MainActor
final class WalletStore: ObservableObject {

    @Published var address: String?
    @Published var publicKeyHex: String?
    /// Shown exactly ONCE right after creation — the only backup. Never persisted.
    @Published var mnemonicToBackUp: String?
    @Published var balanceSats: UInt64?
    @Published var chainHeight: UInt64?
    @Published var lastBroadcastResponse: String?
    @Published var isBusy = false
    @Published var errorMessage: String?

    private let rpc: NodeRpc
    private let testnet: Bool

    /// The in-memory wallet engine. Its secret material is zeroized on drop (Rust).
    private var wallet: Wallet?

    init(
        nodeEndpoint: URL = URL(string: "http://127.0.0.1:8332/")!,
        testnet: Bool = true
    ) {
        self.rpc = NodeRpc(endpoint: nodeEndpoint)
        self.testnet = testnet
    }

    /// Create a brand-new wallet; surfaces the mnemonic once for the user to back up.
    func createWallet() {
        run {
            // SDK `NewWallet` is an opaque handle (not a struct): the mnemonic
            // never crosses as a printable field. Take the live wallet directly
            // via `wallet()` (no mnemonic round-trip) and reveal the backup ONCE.
            let fresh: NewWallet = try generateWallet(testnet: self.testnet)
            self.wallet = fresh.wallet()
            let mnemonic = try fresh.revealMnemonic()   // one-shot; wiped Rust-side
            self.address = fresh.address()
            self.publicKeyHex = fresh.publicKeyHex()
            self.mnemonicToBackUp = mnemonic
            self.balanceSats = nil
            self.lastBroadcastResponse = nil
            try await self.refreshBalanceInternal()
        }
    }

    /// Restore a wallet from a user-supplied BIP39 mnemonic.
    func restore(mnemonic: String) {
        run {
            let w = try Wallet.fromMnemonic(
                phrase: mnemonic.trimmingCharacters(in: .whitespacesAndNewlines),
                testnet: self.testnet
            )
            self.wallet = w
            self.address = w.address()
            self.publicKeyHex = w.publicKeyHex()
            self.mnemonicToBackUp = nil
            self.balanceSats = nil
            self.lastBroadcastResponse = nil
            try await self.refreshBalanceInternal()
        }
    }

    /// The user has recorded the mnemonic; clear it from state.
    func dismissMnemonicBackup() {
        mnemonicToBackUp = nil
    }

    /// Pull the current balance + chain height from the node.
    func refreshBalance() {
        run { try await self.refreshBalanceInternal() }
    }

    private func refreshBalanceInternal() async throws {
        guard let address else { return }
        let balance = try await rpc.getBalance(address: address)
        let height = try? await rpc.getBlockCount()
        self.balanceSats = balance
        self.chainHeight = height
    }

    /// Send stub: signs an unsigned transaction hex with the core's `signTxHex`
    /// and broadcasts it. A full build assembles the unsigned tx from UTXOs
    /// fetched over RPC; here we take the unsigned hex directly to keep the
    /// signing path honest (a real `signTxHex` call, not a fake).
    func signAndBroadcast(unsignedTxHex: String) {
        run {
            guard let w = self.wallet else {
                throw PosternError.Postern(msg: "no wallet loaded")
            }
            let signedHex = try w.signTxHex(unsignedTxHex: unsignedTxHex) // hybrid PQ signature
            self.lastBroadcastResponse = try await self.rpc.sendRawTransaction(signedTxHex: signedHex)
        }
    }

    /// Common busy/error wrapper for the async actions.
    private func run(_ block: @escaping () async throws -> Void) {
        Task {
            isBusy = true
            errorMessage = nil
            do {
                try await block()
            } catch let error as PosternError {
                errorMessage = errorText(error)
            } catch {
                errorMessage = error.localizedDescription
            }
            isBusy = false
        }
    }

    private func errorText(_ error: PosternError) -> String {
        switch error {
        case let .Postern(msg): return msg
        }
    }
}
