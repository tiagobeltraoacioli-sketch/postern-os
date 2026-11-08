import CryptoKit
import DeviceCheck
import Foundation
import Security

/// Secure Enclave key + **App Attest** attestation — the iOS form of the
/// **Postern Seal**.
///
/// Two hardware facilities, both classical:
///  1. A **Secure Enclave** P-256 key (`kSecAttrTokenIDSecureEnclave`) whose
///     private half never leaves the Enclave. We use it to WRAP the wallet
///     secret at rest (the PQ key material is sealed to this hardware key).
///  2. **App Attest** (`DCAppAttestService`): a hardware-backed attestation
///     chaining to Apple's CA that proves a genuine, unmodified app on genuine
///     hardware. We bind the node/verifier **nonce** into the assertion so a
///     verifier can echo the nonce it issued (via `getattestation`) and run
///     `bloch::attestation::verify` with the `mobile` backend.
///
/// HONEST LIMIT (see mobile/README.md): the Secure Enclave is a CLASSICAL P-256
/// coprocessor. It does NOT hold the post-quantum (Falcon‖ML-DSA) wallet key IN
/// hardware. Its role is (a) attest the device/app, and (b) protect the PQ key
/// material AT REST by wrapping it. PQ signing runs in the Rust core, in RAM
/// (zeroized on drop). Light-client role only — never a miner.
enum SecureEnclaveKey {

    enum KeyError: LocalizedError {
        case unsupported(String)
        case secItem(OSStatus)
        case attest(String)

        var errorDescription: String? {
            switch self {
            case let .unsupported(m): return m
            case let .secItem(s): return "Keychain/SecItem error: \(s)"
            case let .attest(m): return "App Attest error: \(m)"
            }
        }
    }

    private static let keyTag = "labs.postern.wallet.wrap".data(using: .utf8)!

    // MARK: - Secure Enclave wrapping key

    /// Create (or return existing) the Secure Enclave P-256 key used to wrap the
    /// wallet secret at rest. Requires a device with a Secure Enclave.
    @discardableResult
    static func makeWrappingKey(requireBiometry: Bool = true) throws -> SecKey {
        if let existing = try loadWrappingKey() { return existing }

        guard SecureEnclave.isAvailable else {
            throw KeyError.unsupported("Secure Enclave not available on this device")
        }

        var accessError: Unmanaged<CFError>?
        let flags: SecAccessControlCreateFlags = requireBiometry
            ? [.privateKeyUsage, .userPresence]
            : [.privateKeyUsage]
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &accessError
        ) else {
            throw KeyError.attest("SecAccessControl: \(accessError!.takeRetainedValue())")
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave, // → private key stays in the Enclave
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: keyTag,
                kSecAttrAccessControl as String: access,
            ],
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw KeyError.attest("SecKeyCreateRandomKey: \(error!.takeRetainedValue())")
        }
        return key
    }

    /// Load the previously created Secure Enclave wrapping key, if any.
    static func loadWrappingKey() throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            return (item as! SecKey)
        case errSecItemNotFound:
            return nil
        default:
            throw KeyError.secItem(status)
        }
    }

    // MARK: - App Attest (the Postern Seal over a node nonce)

    /// Generate an App Attest key + attestation object bound to `nonce`.
    ///
    /// `nonce` is the node/verifier challenge; App Attest hashes the client data
    /// (containing the nonce) into the attestation so a verifier can confirm the
    /// echo. Returns `(keyId, attestationObject)` — hand both to the verifier.
    static func attest(nonce: Data) async throws -> (keyId: String, attestation: Data) {
        let service = DCAppAttestService.shared
        guard service.isSupported else {
            throw KeyError.unsupported("App Attest not supported on this device")
        }

        let keyId = try await service.generateKey()
        // Apple requires the client-data HASH (SHA-256) as the attestation input.
        let clientDataHash = Data(SHA256.hash(data: nonce))
        let attestation = try await service.attestKey(keyId, clientDataHash: clientDataHash)
        return (keyId, attestation)
    }

    /// Produce an App Attest *assertion* over a later node nonce (after the key
    /// was attested once). Proves continued possession on the same genuine app.
    static func assert(keyId: String, nonce: Data) async throws -> Data {
        let service = DCAppAttestService.shared
        let clientDataHash = Data(SHA256.hash(data: nonce))
        return try await service.generateAssertion(keyId, clientDataHash: clientDataHash)
    }
}
