package labs.postern.wallet

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

// UniFFI-generated helpers from the unified Postern SDK facade
// (crates/postern-sdk). The Rust core SHAPES the JSON-RPC request bodies +
// PARSES the responses; this Kotlin class only performs the network I/O (the
// pure/impure split described in mobile/README.md).
import uniffi.postern_sdk.parseU64Result
import uniffi.postern_sdk.rpcGetattestation
import uniffi.postern_sdk.rpcGetbalance
import uniffi.postern_sdk.rpcGetblockcount
import uniffi.postern_sdk.rpcRequest

/**
 * Thin HTTP client for a Bloch-SIS-PoW node's JSON-RPC endpoint.
 *
 * Request bodies and response parsing come from the Rust core (byte-compatible
 * with the node); this class is purely the OkHttp transport.
 */
class NodeRpc(
    private val endpoint: String,
    private val client: OkHttpClient = defaultClient(),
) {
    /** Balance (in sats) for [address], via the core's `getbalance` builder + parser. */
    suspend fun getBalance(address: String): ULong {
        val body = rpcGetbalance(address)          // core builds the JSON-RPC body
        val response = post(body)
        return parseU64Result(response)            // core parses `result` → u64
    }

    /** Current chain height, for a sync / liveness indicator. */
    suspend fun getBlockCount(): ULong {
        val response = post(rpcGetblockcount())
        return parseU64Result(response)
    }

    /**
     * Fetch a device-attestation challenge (nonce) from the node. The app then
     * mints a Key-Attestation chain over this nonce — the mobile Postern Seal.
     * Returns the raw JSON-RPC response for the caller to extract the nonce from.
     */
    suspend fun getAttestationChallenge(nonce: String): String =
        post(rpcGetattestation(nonce))

    /**
     * Broadcast a signed transaction hex via `sendrawtransaction`. `paramsJson`
     * is a raw JSON array; the core validates + frames it into a request body.
     */
    suspend fun sendRawTransaction(signedTxHex: String): String {
        val body = rpcRequest("sendrawtransaction", "[\"$signedTxHex\"]")
        return post(body)
    }

    private suspend fun post(jsonBody: String): String = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(endpoint)
            .post(jsonBody.toRequestBody(JSON))
            .build()
        client.newCall(request).execute().use { resp ->
            val text = resp.body?.string().orEmpty()
            if (!resp.isSuccessful) {
                throw RpcException("HTTP ${resp.code} from node: $text")
            }
            text
        }
    }

    companion object {
        private val JSON = "application/json; charset=utf-8".toMediaType()

        private fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .build()
    }
}

class RpcException(message: String) : Exception(message)
