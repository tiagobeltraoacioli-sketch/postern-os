import SwiftUI

/// The single wallet screen: create / restore, show the address + balance, and
/// a send stub. Deliberately minimal — this is the skeleton's UI surface.
struct ContentView: View {
    @EnvironmentObject private var store: WalletStore

    @State private var mnemonicInput: String = ""
    @State private var unsignedTxHex: String = ""

    var body: some View {
        NavigationStack {
            Form {
                if store.address == nil {
                    createOrRestoreSection
                } else {
                    walletSection
                    sendStubSection
                }

                if let mnemonic = store.mnemonicToBackUp {
                    mnemonicBackupSection(mnemonic)
                }

                if let error = store.errorMessage {
                    Section {
                        Text(error).foregroundStyle(.red)
                    }
                }

                if let response = store.lastBroadcastResponse {
                    Section("Last broadcast response") {
                        Text(response).font(.system(.footnote, design: .monospaced))
                    }
                }
            }
            .navigationTitle("Postern Wallet")
            .overlay {
                if store.isBusy { ProgressView() }
            }
        }
    }

    // MARK: - Sections

    private var createOrRestoreSection: some View {
        Section {
            Button("Create new wallet") { store.createWallet() }
                .disabled(store.isBusy)

            VStack(alignment: .leading, spacing: 8) {
                Text("Or restore from a BIP39 recovery phrase").font(.footnote)
                TextField("recovery phrase", text: $mnemonicInput, axis: .vertical)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .lineLimit(2...4)
                Button("Restore wallet") { store.restore(mnemonic: mnemonicInput) }
                    .disabled(store.isBusy || mnemonicInput.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        } header: {
            Text("Light client for the ownerless Bloch-SIS-PoW protocol")
        }
    }

    private var walletSection: some View {
        Section("Wallet") {
            VStack(alignment: .leading, spacing: 4) {
                Text("Receiving address").font(.caption).foregroundStyle(.secondary)
                Text(store.address ?? "—")
                    .font(.system(.footnote, design: .monospaced))
                    .textSelection(.enabled)
            }
            HStack {
                Text("Balance")
                Spacer()
                Text(store.balanceSats.map { "\($0) sats" } ?? "—")
                    .foregroundStyle(.secondary)
            }
            if let height = store.chainHeight {
                HStack {
                    Text("Chain height")
                    Spacer()
                    Text("\(height)").foregroundStyle(.secondary)
                }
            }
            Button("Refresh balance") { store.refreshBalance() }
                .disabled(store.isBusy)
        }
    }

    private var sendStubSection: some View {
        // Send STUB: a real build assembles the unsigned tx from UTXOs (fetched
        // over RPC) for a recipient + amount. Here we accept the unsigned tx hex
        // directly so the signing path (core `signTxHex`) stays real, not faked.
        Section("Send (stub)") {
            TextField("unsigned tx hex", text: $unsignedTxHex, axis: .vertical)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .font(.system(.footnote, design: .monospaced))
                .lineLimit(2...4)
            Button("Sign & broadcast") {
                store.signAndBroadcast(unsignedTxHex: unsignedTxHex.trimmingCharacters(in: .whitespacesAndNewlines))
            }
            .disabled(store.isBusy || unsignedTxHex.trimmingCharacters(in: .whitespaces).isEmpty)
        }
    }

    private func mnemonicBackupSection(_ mnemonic: String) -> some View {
        Section {
            Text("Back up this recovery phrase — it is the ONLY backup and is shown once.")
                .font(.subheadline).bold()
            Text(mnemonic)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
            Button("I saved it") { store.dismissMnemonicBackup() }
        } header: {
            Text("Recovery phrase")
        }
    }
}

#Preview {
    ContentView().environmentObject(WalletStore())
}
