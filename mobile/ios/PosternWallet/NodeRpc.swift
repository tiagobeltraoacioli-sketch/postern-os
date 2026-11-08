import Foundation

// UniFFI-generated Swift surface from the unified Postern SDK facade
// (crates/postern-sdk). The Rust core SHAPES the JSON-RPC bodies + PARSES
// responses (byte-compatible with the node); this file only performs the
// URLSession network I/O.
import postern_sdk

/// Thin HTTP client for a Bloch-SIS-PoW node's JSON-RPC endpoint.
///
/// Request bodies and response parsing come from the Rust core; this type is
/// purely the URLSession transport (the pure/impure split — see mobile/README.md).
struct NodeRpc {
    let endpoint: URL
    private let session: URLSession

    init(endpoint: URL, session: URLSession = .shared) {
        self.endpoint = endpoint
        self.session = session
    }

    /// Balance (in sats) for `address`, via the core's `getbalance` builder + parser.
    func getBalance(address: String) async throws -> UInt64 {
        let body = rpcGetbalance(address: address)      // core builds the JSON-RPC body
        let response = try await post(body)
        return try parseU64Result(responseJson: response) // core parses `result` → u64
    }

    /// Current chain height, for a sync / liveness indicator.
    func getBlockCount() async throws -> UInt64 {
        let response = try await post(rpcGetblockcount())
        return try parseU64Result(responseJson: response)
    }

    /// Fetch a device-attestation challenge (nonce) from the node. The app then
    /// mints an App Attest assertion over it — the mobile Postern Seal. Returns
    /// the raw JSON-RPC response for the caller to extract the nonce from.
    func getAttestationChallenge(nonce: String) async throws -> String {
        try await post(rpcGetattestation(nonce: nonce))
    }

    /// Broadcast a signed transaction hex via `sendrawtransaction`. The core
    /// validates the raw params JSON and frames it into a request body.
    func sendRawTransaction(signedTxHex: String) async throws -> String {
        let body = try rpcRequest(method: "sendrawtransaction", paramsJson: "[\"\(signedTxHex)\"]")
        return try await post(body)
    }

    private func post(_ jsonBody: String) async throws -> String {
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data(jsonBody.utf8)

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw RpcError.transport("no HTTP response from node")
        }
        let text = String(decoding: data, as: UTF8.self)
        guard (200..<300).contains(http.statusCode) else {
            throw RpcError.transport("HTTP \(http.statusCode) from node: \(text)")
        }
        return text
    }
}

enum RpcError: LocalizedError {
    case transport(String)

    var errorDescription: String? {
        switch self {
        case let .transport(message): return message
        }
    }
}
