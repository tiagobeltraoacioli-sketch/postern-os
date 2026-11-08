import SwiftUI

/// Postern Wallet — a Postern Labs product.
///
/// A light client / wallet for the ownerless Bloch-SIS-PoW protocol. All wallet
/// crypto is delegated to the Rust core (`bloch-mobile`) via UniFFI; SwiftUI is
/// only the UI + platform I/O (URLSession, Secure Enclave, App Attest).
@main
struct PosternWalletApp: App {
    @StateObject private var store = WalletStore()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(store)
        }
    }
}
