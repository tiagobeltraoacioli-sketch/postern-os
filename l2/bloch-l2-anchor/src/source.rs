//! Chain read access for the anchor reader: the [`BlockSource`] trait +
//! [`MockChain`].
//!
//! [`BlockSource`] is shaped **exactly** on the node's documented JSON-RPC
//! surface (`docs/openapi.yaml` in the BlochSISPoW repo — single `POST /`
//! endpoint, JSON-RPC 2.0), one-to-one with `bloch-tokens`'
//! `stream::BlockSource` so the two readers share the same reorg discipline:
//!
//! | trait method                | JSON-RPC method                          |
//! |-----------------------------|------------------------------------------|
//! | [`BlockSource::tip_height`] | `getblockcount` (tip = count − 1)        |
//! | [`BlockSource::block_hash`] | `getblockhash(height)`                   |
//! | [`BlockSource::block_by_height`] | `getblockbyheight(height, verbose=true)` |
//!
//! All three are **reads** — the read RPC is public on every node, which is
//! what keeps the anchor layer permissionless: anyone can point an anchor
//! reader at any node (their own included) with no key and no privilege, and
//! must derive the same canonical anchor chain.
//!
//! **The default build is zero-dependency and offline** — no tokio, no HTTP
//! dependency (same stance as `bloch-tokens`), and [`MockChain`] stands in for
//! the node so the reader — including its reorg handling — is exercised fully
//! offline and deterministically.
//!
//! A **real** read-only client lives behind the OFF-by-default `http` feature:
//! [`HttpBlockSource`] (see below) POSTs
//! `{"jsonrpc":"2.0","method":...,"params":[...],"id":1}` to a node and maps
//! the node's non-standard in-`result` error quirk (method-level failures —
//! unknown/pruned height — arrive as `{"result":{"error":…}}` with HTTP 200,
//! *not* a top-level JSON-RPC error) to [`SourceError::HeightNotFound`]. It is
//! hand-rolled on `std` only, so enabling the feature still pulls in zero
//! third-party crates, and it is strictly READ — it never writes to, restarts,
//! or reconfigures a node.
//!
//! Height/DAG note: Bloch is a BlockDAG; `getblockbyheight` serves the node's
//! **selected chain** view, which is what a reader replays. A reorg
//! (selected-chain change) shows up as `getblockhash(h)` returning a
//! different hash for an already-seen height — exactly what
//! [`crate::manager::AnchorManager::sync`] detects.
//! [`MockChain::replace_suffix`] forces that situation in tests.

use crate::envelope::Tx;

/// A block hash (`Hex32` in openapi.yaml), as raw bytes.
pub type BlockHash = [u8; 32];

/// Read-path failure. `HeightNotFound` mirrors the node's non-standard
/// `result.error` on `getblockhash`/`getblockbyheight`; `EmptyChain` is
/// `getblockcount == 0` (no tip yet); `Transport` is reserved for real
/// clients (network/serialization) and misbehaving sources.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceError {
    /// `getblockcount == 0`: the chain has no blocks yet.
    EmptyChain,
    /// The requested height is absent (node returned a method-level error).
    HeightNotFound(u64),
    /// Network/serialization failure, or a source that returned malformed or
    /// self-inconsistent data.
    Transport(String),
}

impl core::fmt::Display for SourceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyChain => write!(f, "source: chain has no blocks (getblockcount == 0)"),
            Self::HeightNotFound(h) => write!(f, "source: height {h} not found"),
            Self::Transport(msg) => write!(f, "source: transport failure: {msg}"),
        }
    }
}

impl std::error::Error for SourceError {}

/// One selected-chain transaction: its txid plus the structural body the
/// anchor reader needs (via [`crate::envelope::extract_anchor`]).
///
/// `txid` comes from the node (`getblockbyheight` returns it); the zero-dep
/// anchor crate never hashes a transaction itself. The body is the crate's
/// [`Tx`] mirror — the same reduced view [`crate::envelope`] extracts from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceTx {
    /// Transaction id as reported by the node.
    pub txid: [u8; 32],
    /// Structural body an anchor reader inspects.
    pub tx: Tx,
}

/// The selected-chain view of one block: the subset of the node's `Block`
/// schema (openapi.yaml, `verbose=true`) that the anchor layer reads — hash,
/// height, and transactions (txid + body).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// Block hash (`getblockhash(height)`).
    pub hash: BlockHash,
    /// Selected-chain height of this block (heights start at 0).
    pub height: u64,
    /// Transactions in the block, in block order.
    pub transactions: Vec<SourceTx>,
}

/// Read-only access to the selected chain, shaped on the documented node RPC
/// (see module docs for the method mapping). Implemented by [`MockChain`]
/// here; a real JSON-RPC client is out of scope by design.
pub trait BlockSource {
    /// Current tip height (`getblockcount` − 1).
    /// [`SourceError::EmptyChain`] when the count is 0.
    fn tip_height(&self) -> Result<u64, SourceError>;

    /// Hash of the selected-chain block at `height` (`getblockhash`).
    fn block_hash(&self, height: u64) -> Result<BlockHash, SourceError>;

    /// Full block at `height` (`getblockbyheight(height, verbose=true)`).
    fn block_by_height(&self, height: u64) -> Result<Block, SourceError>;
}

// ── MockChain ─────────────────────────────────────────────────────────────────

/// In-memory stand-in for the node's read RPC: an append-only selected chain
/// (heights start at 0) that can also be **forced to reorg** by replacing a
/// suffix of blocks ([`MockChain::replace_suffix`]). Mirrors
/// `bloch-tokens::stream::MockChain`.
///
/// Block hashes are produced by a deterministic mixing function (FNV-1a
/// lanes) over `(height, uniq, parent hash, txids)` — **not cryptographic,
/// mock-only**. `uniq` is a monotonic counter, so a replacement block at an
/// already-used height always hashes differently even with identical
/// transactions, which is exactly what a reorged real chain looks like to
/// `getblockhash`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MockChain {
    blocks: Vec<Block>,
    uniq: u64,
}

impl MockChain {
    /// A fresh empty chain (`getblockcount == 0`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of blocks (== `getblockcount`).
    pub fn block_count(&self) -> u64 {
        self.blocks.len() as u64
    }

    /// Append a block at the next height carrying `transactions`; returns its
    /// hash.
    pub fn append(&mut self, transactions: Vec<SourceTx>) -> BlockHash {
        let height = self.blocks.len() as u64;
        let parent = self.blocks.last().map(|b| b.hash).unwrap_or([0u8; 32]);
        self.uniq += 1;
        let hash = mock_block_hash(height, &parent, &transactions, self.uniq);
        self.blocks.push(Block { hash, height, transactions });
        hash
    }

    /// Force a reorg: drop every block at height >= `from_height`, then append
    /// the replacement blocks in order. The `uniq` counter never resets, so
    /// replacement blocks hash differently from the ones they replace — a
    /// reader sees a hash mismatch at `from_height`.
    pub fn replace_suffix(&mut self, from_height: u64, replacement: Vec<Vec<SourceTx>>) {
        self.blocks.truncate(from_height as usize);
        for txs in replacement {
            self.append(txs);
        }
    }
}

impl BlockSource for MockChain {
    fn tip_height(&self) -> Result<u64, SourceError> {
        match self.blocks.len() {
            0 => Err(SourceError::EmptyChain),
            n => Ok(n as u64 - 1),
        }
    }

    fn block_hash(&self, height: u64) -> Result<BlockHash, SourceError> {
        self.blocks
            .get(height as usize)
            .map(|b| b.hash)
            .ok_or(SourceError::HeightNotFound(height))
    }

    fn block_by_height(&self, height: u64) -> Result<Block, SourceError> {
        self.blocks
            .get(height as usize)
            .cloned()
            .ok_or(SourceError::HeightNotFound(height))
    }
}

/// Deterministic 32-byte mixing function (four FNV-1a-64 lanes with distinct
/// seeds). NOT cryptographic — collision-resistance is irrelevant for a test
/// mock; determinism and sensitivity to every input byte are what matter.
fn mock_block_hash(height: u64, parent: &BlockHash, txs: &[SourceTx], uniq: u64) -> BlockHash {
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    let mut lanes = [
        FNV_OFFSET ^ 0x9e37_79b9_7f4a_7c15,
        FNV_OFFSET ^ 0x6a09_e667_f3bc_c908,
        FNV_OFFSET ^ 0xbb67_ae85_84ca_a73b,
        FNV_OFFSET ^ 0x3c6e_f372_fe94_f82b,
    ];
    let mut feed = |bytes: &[u8]| {
        for (i, b) in bytes.iter().enumerate() {
            let lane = &mut lanes[i % 4];
            *lane ^= u64::from(*b);
            *lane = lane.wrapping_mul(FNV_PRIME);
        }
        // Lane separator so field boundaries matter.
        for lane in &mut lanes {
            *lane ^= 0xff;
            *lane = lane.wrapping_mul(FNV_PRIME);
        }
    };
    feed(&height.to_le_bytes());
    feed(&uniq.to_le_bytes());
    feed(parent);
    for tx in txs {
        feed(&tx.txid);
    }
    let mut out = [0u8; 32];
    for (i, lane) in lanes.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&lane.to_le_bytes());
    }
    out
}

// ── HTTP JSON-RPC BlockSource (optional `http` feature) ─────────────────────────
//
// REAL, read-only client wiring [`BlockSource`] to a live Bloch node's public
// JSON-RPC. OFF by default; enabled with `--features http`. Deliberately
// `std`-only (no tokio, no reqwest, no serde) so the *whole* crate — feature on
// or off — stays zero-dependency and offline-buildable, the same stance the
// rest of the crate takes. It is strictly READ (getblockcount / getblockhash /
// getblockbyheight); it never writes, restarts, or reconfigures a node.

#[cfg(feature = "http")]
pub use http_source::HttpBlockSource;

#[cfg(feature = "http")]
mod http_source {
    use super::{Block, BlockHash, BlockSource, SourceError, SourceTx};
    use crate::envelope::{Tx, TxIn, TxOut};
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    /// Read-only JSON-RPC client for a Bloch node, implementing
    /// [`BlockSource`] over the node's documented `POST /` endpoint.
    ///
    /// # The node's in-`result` error quirk
    ///
    /// The Bloch node reports **method-level** failures (an unknown height, a
    /// pruned block) NOT as a JSON-RPC top-level `error`, but as an object
    /// *inside* `result` — `{"jsonrpc":"2.0","id":1,"result":{"error":"height
    /// not found"}}` — returned with **HTTP 200**. (Top-level `error` is
    /// reserved for transport-ish failures: auth `-32001`, rate-limit `-32002`.)
    /// This client maps an in-`result` error to
    /// [`SourceError::HeightNotFound`], and a top-level `error` / non-200
    /// status to [`SourceError::Transport`]. Verified against the live node
    /// at rev with `getblockcount`/`getblockhash`/`getblockbyheight`.
    ///
    /// # Read-only, permissionless
    ///
    /// All three RPCs are public reads on every node (auth gates writes only),
    /// which is what keeps the anchor layer permissionless — point this at
    /// your own node or any read-only public node, no key, no privilege. An
    /// optional API key header is supported for nodes that gate reads too, but
    /// it is never required for the canonical read path.
    ///
    /// # Not TLS
    ///
    /// Plain HTTP only (`http://…`) — a local node you run, or a read-only
    /// public node over HTTP. TLS is out of scope for a zero-dep `std`-only
    /// client; front a public node with a local reverse proxy if you need it.
    #[derive(Clone, Debug)]
    pub struct HttpBlockSource {
        host: String,
        port: u16,
        path: String,
        api_key: Option<String>,
        timeout: Duration,
    }

    impl HttpBlockSource {
        /// Build a client from an `http://host[:port][/path]` URL. Defaults:
        /// port `16210` (the node's default `--rpc-port`), path `/`, 30s
        /// timeout, no API key. Returns [`SourceError::Transport`] on a URL
        /// this minimal parser cannot handle (non-`http`, empty host, bad
        /// port).
        pub fn new(url: &str) -> Result<Self, SourceError> {
            let rest = url
                .strip_prefix("http://")
                .ok_or_else(|| SourceError::Transport(format!("only http:// URLs supported: {url}")))?;
            // Split authority from path at the first '/'.
            let (authority, path) = match rest.find('/') {
                Some(i) => (&rest[..i], rest[i..].to_string()),
                None => (rest, "/".to_string()),
            };
            if authority.is_empty() {
                return Err(SourceError::Transport(format!("empty host in URL: {url}")));
            }
            let (host, port) = match authority.rfind(':') {
                Some(i) => {
                    let p = authority[i + 1..]
                        .parse::<u16>()
                        .map_err(|_| SourceError::Transport(format!("bad port in URL: {url}")))?;
                    (authority[..i].to_string(), p)
                }
                None => (authority.to_string(), 16210),
            };
            if host.is_empty() {
                return Err(SourceError::Transport(format!("empty host in URL: {url}")));
            }
            Ok(Self { host, port, path, api_key: None, timeout: Duration::from_secs(30) })
        }

        /// Attach an `X-API-Key` header (for nodes that gate reads; not needed
        /// for the public read path).
        pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
            self.api_key = Some(key.into());
            self
        }

        /// Override the per-request connect/read/write timeout (default 30s).
        pub fn with_timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self
        }

        /// Read-only: the DAG **parent hashes** of the selected-chain block at
        /// `height` (the node's `parents` array). Distinct from
        /// [`BlockSource::block_by_height`], which serves the reduced view the
        /// anchor reader consumes — this exposes the block's DAG ancestry so a
        /// caller can independently verify selected-chain **contiguity**: on
        /// the selected chain `height == selected_parent.height + 1`, so the
        /// block at height `h` always lists the hash of the block at height
        /// `h-1` among its parents. A live anchor reader uses this as a
        /// no-shortcut proof that it replayed a genuinely contiguous band of
        /// real blocks (not isolated/fabricated ones). Strictly READ; maps the
        /// node's in-`result` error quirk to [`SourceError::HeightNotFound`].
        pub fn block_parents(&self, height: u64) -> Result<Vec<BlockHash>, SourceError> {
            let v = self.call("getblockbyheight", &format!("[{height},true]"))?;
            parse_block_parents(&v, height)
        }

        /// POST one JSON-RPC call and return the `result` value. `params` is
        /// the already-serialized array text (e.g. `"[]"`, `"[123]"`,
        /// `"[123,true]"`) — the shapes this client uses are all simple, so no
        /// JSON *serializer* is needed, only the reader.
        fn call(&self, method: &str, params: &str) -> Result<Json, SourceError> {
            let body = format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{method}\",\"params\":{params}}}"
            );
            let raw = self.post(&body)?;
            let (status, resp_body) = split_http(&raw)?;
            if status != 200 {
                return Err(SourceError::Transport(format!(
                    "http {status} from node: {}",
                    truncate(&resp_body, 200)
                )));
            }
            let v = Json::parse(&resp_body)
                .map_err(|e| SourceError::Transport(format!("malformed JSON from node: {e}")))?;
            // Top-level `error` (auth / rate-limit / parse) is a transport-class
            // failure — distinct from the in-`result` method error quirk.
            if let Some(err) = v.get("error") {
                if !err.is_null() {
                    return Err(SourceError::Transport(format!(
                        "node returned top-level error: {}",
                        truncate(&resp_body, 200)
                    )));
                }
            }
            v.into_get("result")
                .ok_or_else(|| SourceError::Transport("response has no `result`".into()))
        }

        /// Raw HTTP/1.1 POST to the node; returns the full response bytes as a
        /// `String` (headers + body). `Connection: close` so we read to EOF.
        fn post(&self, body: &str) -> Result<String, SourceError> {
            let addr = format!("{}:{}", self.host, self.port);
            let mut stream = {
                use std::net::ToSocketAddrs;
                let mut sockaddrs = addr
                    .to_socket_addrs()
                    .map_err(|e| SourceError::Transport(format!("resolve {addr}: {e}")))?;
                let sa = sockaddrs
                    .next()
                    .ok_or_else(|| SourceError::Transport(format!("no address for {addr}")))?;
                TcpStream::connect_timeout(&sa, self.timeout)
                    .map_err(|e| SourceError::Transport(format!("connect {addr}: {e}")))?
            };
            stream
                .set_read_timeout(Some(self.timeout))
                .and_then(|_| stream.set_write_timeout(Some(self.timeout)))
                .map_err(|e| SourceError::Transport(format!("set timeout: {e}")))?;

            let mut req = String::new();
            req.push_str(&format!("POST {} HTTP/1.1\r\n", self.path));
            req.push_str(&format!("Host: {}:{}\r\n", self.host, self.port));
            req.push_str("Content-Type: application/json\r\n");
            req.push_str(&format!("Content-Length: {}\r\n", body.len()));
            if let Some(k) = &self.api_key {
                req.push_str(&format!("X-API-Key: {k}\r\n"));
            }
            req.push_str("Connection: close\r\n\r\n");
            req.push_str(body);

            stream
                .write_all(req.as_bytes())
                .map_err(|e| SourceError::Transport(format!("write: {e}")))?;
            stream
                .flush()
                .map_err(|e| SourceError::Transport(format!("flush: {e}")))?;

            let mut buf = Vec::new();
            stream
                .read_to_end(&mut buf)
                .map_err(|e| SourceError::Transport(format!("read: {e}")))?;
            String::from_utf8(buf)
                .map_err(|_| SourceError::Transport("non-UTF8 response".into()))
        }
    }

    impl BlockSource for HttpBlockSource {
        fn tip_height(&self) -> Result<u64, SourceError> {
            // `result` is a bare integer (the block count). tip = count - 1;
            // count == 0 is the empty chain.
            let count = self
                .call("getblockcount", "[]")?
                .as_u64()
                .ok_or_else(|| SourceError::Transport("getblockcount: result not an integer".into()))?;
            count.checked_sub(1).ok_or(SourceError::EmptyChain)
        }

        fn block_hash(&self, height: u64) -> Result<BlockHash, SourceError> {
            // `result` is a 64-hex string on success, or the in-`result`
            // {"error": …} object on a missing height.
            let v = self.call("getblockhash", &format!("[{height}]"))?;
            match v.as_str() {
                Some(hex) => hex32(hex)
                    .ok_or_else(|| SourceError::Transport(format!("getblockhash: bad hash {hex:?}"))),
                None => Err(map_result_error(&v, height)),
            }
        }

        fn block_by_height(&self, height: u64) -> Result<Block, SourceError> {
            // `result` is the block object (verbose=true) on success, or the
            // in-`result` {"error": …} object on a missing/pruned height.
            let v = self.call("getblockbyheight", &format!("[{height},true]"))?;
            // A block object always carries "hash" and "height"; the error
            // object carries only "error". Absence of the block fields ⇒ the
            // node's in-`result` error quirk ⇒ HeightNotFound.
            let hash_str = match v.get("hash").and_then(Json::as_str) {
                Some(s) => s,
                None => return Err(map_result_error(&v, height)),
            };
            let hash = hex32(hash_str)
                .ok_or_else(|| SourceError::Transport(format!("block hash malformed: {hash_str:?}")))?;
            let got_height = v
                .get("height")
                .and_then(Json::as_u64)
                .ok_or_else(|| SourceError::Transport("block has no integer height".into()))?;
            let txs_json = v
                .get("transactions")
                .and_then(Json::as_array)
                .ok_or_else(|| SourceError::Transport("block has no transactions array".into()))?;
            let mut transactions = Vec::with_capacity(txs_json.len());
            for t in txs_json {
                transactions.push(parse_source_tx(t)?);
            }
            Ok(Block { hash, height: got_height, transactions })
        }
    }

    /// Map an in-`result` error object (`{"error": "..."}`) to a typed source
    /// error. Any recognized "not found" / pruned message becomes
    /// [`SourceError::HeightNotFound`]; anything else is surfaced as transport.
    fn map_result_error(v: &Json, height: u64) -> SourceError {
        match v.get("error").and_then(Json::as_str) {
            // "height not found", "block data not found", "not found" — every
            // absence-class message the node returns for these read RPCs.
            Some(msg) if msg.contains("not found") => SourceError::HeightNotFound(height),
            Some(msg) => SourceError::Transport(format!("node result error at height {height}: {msg}")),
            None => SourceError::Transport(format!(
                "unexpected result shape at height {height} (no hash, no error)"
            )),
        }
    }

    /// Parse a verbose block's `parents` array (DAG parent hashes) from a
    /// `getblockbyheight` result. A real block object always carries `hash`;
    /// its absence is the node's in-`result` error quirk ⇒
    /// [`SourceError::HeightNotFound`]. A block with no `parents` field (or an
    /// empty one — genesis) yields an empty vector, never an error.
    fn parse_block_parents(v: &Json, height: u64) -> Result<Vec<BlockHash>, SourceError> {
        if v.get("hash").and_then(Json::as_str).is_none() {
            return Err(map_result_error(v, height));
        }
        let mut parents = Vec::new();
        if let Some(arr) = v.get("parents").and_then(Json::as_array) {
            for p in arr {
                let h = p.as_str().and_then(hex32).ok_or_else(|| {
                    SourceError::Transport(format!("parent hash malformed at height {height}"))
                })?;
                parents.push(h);
            }
        }
        Ok(parents)
    }

    /// Parse one transaction from the node's `format_tx` shape into a
    /// [`SourceTx`]. Only the fields an anchor reader needs are read
    /// (`script_sig`/`sequence`/`coinbase` are ignored — the node already
    /// validated the tx; the anchor layer reads structure only).
    fn parse_source_tx(t: &Json) -> Result<SourceTx, SourceError> {
        let txid = t
            .get("txid")
            .and_then(Json::as_str)
            .and_then(hex32)
            .ok_or_else(|| SourceError::Transport("tx missing/bad txid".into()))?;
        let version = t.get("version").and_then(Json::as_u64).unwrap_or(0) as u32;
        let locktime = t.get("locktime").and_then(Json::as_u64).unwrap_or(0) as u32;

        let mut inputs = Vec::new();
        if let Some(arr) = t.get("inputs").and_then(Json::as_array) {
            for inp in arr {
                let prev_txid = inp
                    .get("prev_txid")
                    .and_then(Json::as_str)
                    .and_then(hex32)
                    .ok_or_else(|| SourceError::Transport("input missing/bad prev_txid".into()))?;
                let prev_index = inp.get("prev_index").and_then(Json::as_u64).unwrap_or(0) as u32;
                inputs.push(TxIn { prev_txid, prev_index });
            }
        }

        let mut outputs = Vec::new();
        if let Some(arr) = t.get("outputs").and_then(Json::as_array) {
            for out in arr {
                let value = out.get("value").and_then(Json::as_u64).unwrap_or(0);
                let script_pubkey = out
                    .get("script_pubkey")
                    .and_then(Json::as_str)
                    .map(hex_bytes)
                    .transpose()
                    .map_err(|_| SourceError::Transport("output script_pubkey not hex".into()))?
                    .unwrap_or_default();
                outputs.push(TxOut { value, script_pubkey });
            }
        }

        Ok(SourceTx { txid, tx: Tx { version, inputs, outputs, locktime } })
    }

    // ── HTTP response splitting ──────────────────────────────────────────────

    /// Split a raw HTTP/1.1 response into (status_code, body). Tolerates the
    /// header/body separator being `\r\n\r\n` (standard) or `\n\n`.
    fn split_http(raw: &str) -> Result<(u16, String), SourceError> {
        let (head, body) = raw
            .split_once("\r\n\r\n")
            .or_else(|| raw.split_once("\n\n"))
            .ok_or_else(|| SourceError::Transport("no HTTP header/body separator".into()))?;
        // Status line: "HTTP/1.1 200 OK".
        let status = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse::<u16>().ok())
            .ok_or_else(|| SourceError::Transport("no HTTP status line".into()))?;
        Ok((status, body.to_string()))
    }

    fn truncate(s: &str, n: usize) -> String {
        if s.len() <= n {
            return s.to_string();
        }
        // Back off to the nearest char boundary at or below `n` (stable-Rust
        // equivalent of the nightly `floor_char_boundary`).
        let mut end = n;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }

    // ── Hex helpers ──────────────────────────────────────────────────────────

    fn hex_val(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }

    /// Decode a hex string to bytes; `Err(())` on odd length or a non-hex char.
    fn hex_bytes(s: &str) -> Result<Vec<u8>, ()> {
        let b = s.as_bytes();
        if b.len() & 1 == 1 {
            return Err(());
        }
        let mut out = Vec::with_capacity(b.len() / 2);
        let mut i = 0;
        while i < b.len() {
            let hi = hex_val(b[i]).ok_or(())?;
            let lo = hex_val(b[i + 1]).ok_or(())?;
            out.push((hi << 4) | lo);
            i += 2;
        }
        Ok(out)
    }

    /// Decode exactly 32 bytes of hex (64 chars) into a [`BlockHash`].
    fn hex32(s: &str) -> Option<BlockHash> {
        let v = hex_bytes(s).ok()?;
        <[u8; 32]>::try_from(v.as_slice()).ok()
    }

    // ── Minimal JSON reader (std-only, no deps) ──────────────────────────────
    //
    // Just enough to read the node's read-RPC responses: objects, arrays,
    // strings (with standard escapes), numbers (kept as text so 64-bit heights
    // never lose precision through f64), booleans, null. Never panics; every
    // malformed input returns Err.

    #[derive(Clone, Debug, PartialEq)]
    enum Json {
        Null,
        Bool(bool),
        /// Number kept as its source text (exact u64 parsing on demand).
        Num(String),
        Str(String),
        Arr(Vec<Json>),
        /// Order-preserving object (small, so linear lookup is fine).
        Obj(Vec<(String, Json)>),
    }

    impl Json {
        fn parse(s: &str) -> Result<Json, String> {
            let bytes = s.as_bytes();
            let mut p = Parser { bytes, pos: 0 };
            p.skip_ws();
            let v = p.value()?;
            p.skip_ws();
            if p.pos != bytes.len() {
                return Err(format!("trailing bytes at offset {}", p.pos));
            }
            Ok(v)
        }

        fn is_null(&self) -> bool {
            matches!(self, Json::Null)
        }

        fn get(&self, key: &str) -> Option<&Json> {
            match self {
                Json::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
                _ => None,
            }
        }

        fn into_get(self, key: &str) -> Option<Json> {
            match self {
                Json::Obj(fields) => fields.into_iter().find(|(k, _)| k == key).map(|(_, v)| v),
                _ => None,
            }
        }

        fn as_str(&self) -> Option<&str> {
            match self {
                Json::Str(s) => Some(s),
                _ => None,
            }
        }

        fn as_array(&self) -> Option<&[Json]> {
            match self {
                Json::Arr(a) => Some(a),
                _ => None,
            }
        }

        fn as_u64(&self) -> Option<u64> {
            match self {
                Json::Num(t) => t.parse::<u64>().ok(),
                _ => None,
            }
        }
    }

    struct Parser<'a> {
        bytes: &'a [u8],
        pos: usize,
    }

    impl<'a> Parser<'a> {
        fn skip_ws(&mut self) {
            while self.pos < self.bytes.len() {
                match self.bytes[self.pos] {
                    b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                    _ => break,
                }
            }
        }

        fn peek(&self) -> Option<u8> {
            self.bytes.get(self.pos).copied()
        }

        fn value(&mut self) -> Result<Json, String> {
            self.skip_ws();
            match self.peek().ok_or("unexpected end of input")? {
                b'{' => self.object(),
                b'[' => self.array(),
                b'"' => Ok(Json::Str(self.string()?)),
                b't' => self.literal("true", Json::Bool(true)),
                b'f' => self.literal("false", Json::Bool(false)),
                b'n' => self.literal("null", Json::Null),
                b'-' | b'0'..=b'9' => self.number(),
                c => Err(format!("unexpected byte {:?} at {}", c as char, self.pos)),
            }
        }

        fn literal(&mut self, lit: &str, val: Json) -> Result<Json, String> {
            let end = self.pos + lit.len();
            if end <= self.bytes.len() && &self.bytes[self.pos..end] == lit.as_bytes() {
                self.pos = end;
                Ok(val)
            } else {
                Err(format!("bad literal at {}", self.pos))
            }
        }

        fn number(&mut self) -> Result<Json, String> {
            let start = self.pos;
            if self.peek() == Some(b'-') {
                self.pos += 1;
            }
            while let Some(c) = self.peek() {
                match c {
                    b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-' => self.pos += 1,
                    _ => break,
                }
            }
            if self.pos == start {
                return Err(format!("empty number at {start}"));
            }
            let text = std::str::from_utf8(&self.bytes[start..self.pos])
                .map_err(|_| "non-UTF8 number".to_string())?;
            Ok(Json::Num(text.to_string()))
        }

        fn string(&mut self) -> Result<String, String> {
            // Assumes current byte is the opening quote.
            self.pos += 1;
            let mut out = String::new();
            loop {
                let c = *self.bytes.get(self.pos).ok_or("unterminated string")?;
                self.pos += 1;
                match c {
                    b'"' => return Ok(out),
                    b'\\' => {
                        let esc = *self.bytes.get(self.pos).ok_or("dangling escape")?;
                        self.pos += 1;
                        match esc {
                            b'"' => out.push('"'),
                            b'\\' => out.push('\\'),
                            b'/' => out.push('/'),
                            b'b' => out.push('\u{08}'),
                            b'f' => out.push('\u{0C}'),
                            b'n' => out.push('\n'),
                            b'r' => out.push('\r'),
                            b't' => out.push('\t'),
                            b'u' => {
                                let cp = self.hex4()?;
                                // Handle surrogate pairs for completeness.
                                if (0xD800..=0xDBFF).contains(&cp) {
                                    if self.bytes.get(self.pos) == Some(&b'\\')
                                        && self.bytes.get(self.pos + 1) == Some(&b'u')
                                    {
                                        self.pos += 2;
                                        let lo = self.hex4()?;
                                        let c = 0x10000
                                            + (((cp - 0xD800) as u32) << 10)
                                            + (lo - 0xDC00) as u32;
                                        out.push(char::from_u32(c).ok_or("bad surrogate")?);
                                    } else {
                                        return Err("unpaired high surrogate".into());
                                    }
                                } else {
                                    out.push(char::from_u32(cp as u32).ok_or("bad \\u escape")?);
                                }
                            }
                            _ => return Err(format!("bad escape \\{}", esc as char)),
                        }
                    }
                    // Raw byte; JSON strings from the node are ASCII/UTF-8. Push
                    // as-is, rebuilding multi-byte UTF-8 verbatim.
                    _ => {
                        if c < 0x80 {
                            out.push(c as char);
                        } else {
                            // Collect the rest of this UTF-8 sequence.
                            let start = self.pos - 1;
                            let len = utf8_len(c);
                            let end = start + len;
                            let slice = self
                                .bytes
                                .get(start..end)
                                .ok_or("truncated UTF-8 in string")?;
                            let s = std::str::from_utf8(slice)
                                .map_err(|_| "invalid UTF-8 in string")?;
                            out.push_str(s);
                            self.pos = end;
                        }
                    }
                }
            }
        }

        fn hex4(&mut self) -> Result<u16, String> {
            let slice = self
                .bytes
                .get(self.pos..self.pos + 4)
                .ok_or("short \\u escape")?;
            let mut v: u16 = 0;
            for &b in slice {
                let d = hex_val(b).ok_or("non-hex in \\u escape")?;
                v = (v << 4) | d as u16;
            }
            self.pos += 4;
            Ok(v)
        }

        fn array(&mut self) -> Result<Json, String> {
            self.pos += 1; // '['
            let mut out = Vec::new();
            self.skip_ws();
            if self.peek() == Some(b']') {
                self.pos += 1;
                return Ok(Json::Arr(out));
            }
            loop {
                out.push(self.value()?);
                self.skip_ws();
                match self.peek() {
                    Some(b',') => {
                        self.pos += 1;
                    }
                    Some(b']') => {
                        self.pos += 1;
                        return Ok(Json::Arr(out));
                    }
                    _ => return Err(format!("expected ',' or ']' at {}", self.pos)),
                }
            }
        }

        fn object(&mut self) -> Result<Json, String> {
            self.pos += 1; // '{'
            let mut out: Vec<(String, Json)> = Vec::new();
            self.skip_ws();
            if self.peek() == Some(b'}') {
                self.pos += 1;
                return Ok(Json::Obj(out));
            }
            loop {
                self.skip_ws();
                if self.peek() != Some(b'"') {
                    return Err(format!("expected object key at {}", self.pos));
                }
                let key = self.string()?;
                self.skip_ws();
                if self.peek() != Some(b':') {
                    return Err(format!("expected ':' at {}", self.pos));
                }
                self.pos += 1;
                let val = self.value()?;
                out.push((key, val));
                self.skip_ws();
                match self.peek() {
                    Some(b',') => {
                        self.pos += 1;
                    }
                    Some(b'}') => {
                        self.pos += 1;
                        return Ok(Json::Obj(out));
                    }
                    _ => return Err(format!("expected ',' or '}}' at {}", self.pos)),
                }
            }
        }
    }

    fn utf8_len(first: u8) -> usize {
        if first >= 0xF0 {
            4
        } else if first >= 0xE0 {
            3
        } else if first >= 0xC0 {
            2
        } else {
            1
        }
    }

    #[cfg(test)]
    mod json_tests {
        use super::*;

        #[test]
        fn parses_getblockcount_shape() {
            let v = Json::parse(r#"{"id":1,"jsonrpc":"2.0","result":415130}"#).unwrap();
            assert_eq!(v.get("result").and_then(Json::as_u64), Some(415130));
        }

        #[test]
        fn parses_getblockhash_ok_and_error_quirk() {
            let ok = Json::parse(
                r#"{"id":1,"jsonrpc":"2.0","result":"78866e30462eea46ba5df34d54fb8c65026565f008ad87252daefc1d8990287c"}"#,
            )
            .unwrap();
            let hash = ok.get("result").and_then(Json::as_str).and_then(hex32);
            assert!(hash.is_some());

            // The in-`result` error quirk: HTTP 200, method error inside result.
            let err = Json::parse(r#"{"id":1,"jsonrpc":"2.0","result":{"error":"height not found"}}"#)
                .unwrap();
            let r = err.get("result").unwrap();
            assert!(r.as_str().is_none());
            assert_eq!(map_result_error(r, 42), SourceError::HeightNotFound(42));
        }

        #[test]
        fn maps_block_data_not_found_to_height_not_found() {
            let err =
                Json::parse(r#"{"result":{"error":"block data not found"}}"#).unwrap();
            let r = err.get("result").unwrap();
            assert_eq!(map_result_error(r, 7), SourceError::HeightNotFound(7));
        }

        #[test]
        fn parses_block_with_envelope_output() {
            // A verbose block carrying one zero-value output whose script_pubkey
            // is an L2V0 envelope (hex), plus one ordinary output.
            let env = crate::envelope::AnchorEnvelope {
                rollup_id: [0xAB; 32],
                batch_index: 9,
                prev_state_root: [0x01; 32],
                new_state_root: [0x02; 32],
                da_commitment: [0x03; 32],
                vkey_hash: [0x04; 32],
            };
            let env_hex: String =
                env.encode().iter().map(|b| format!("{b:02x}")).collect();
            let json = format!(
                r#"{{"result":{{"hash":"{h}","height":412161,"tx_count":1,"transactions":[
                    {{"txid":"{txid}","version":1,"coinbase":false,
                      "inputs":[{{"prev_txid":"{p}","prev_index":3,"sequence":4294967295}}],
                      "outputs":[
                        {{"index":0,"value":0,"bloch":0.0,"script_pubkey":"{env_hex}"}},
                        {{"index":1,"value":546,"bloch":0.00000546,"script_pubkey":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}}
                      ],"locktime":0}}
                ]}}}}"#,
                h = "aa".repeat(32),
                txid = "bb".repeat(32),
                p = "cc".repeat(32),
            );
            let v = Json::parse(&json).unwrap();
            let result = v.get("result").unwrap();
            let tx = &result.get("transactions").and_then(Json::as_array).unwrap()[0];
            let stx = parse_source_tx(tx).unwrap();
            assert_eq!(stx.txid, [0xBB; 32]);
            assert_eq!(stx.tx.version, 1);
            assert_eq!(stx.tx.inputs, vec![TxIn { prev_txid: [0xCC; 32], prev_index: 3 }]);
            assert_eq!(stx.tx.outputs.len(), 2);
            assert_eq!(stx.tx.outputs[0].value, 0);
            // The envelope round-trips: the reader can extract it from the block.
            let (idx, decoded) = crate::envelope::extract_anchor(&stx.tx).unwrap();
            assert_eq!(idx, 0);
            assert_eq!(decoded, env);
        }

        #[test]
        fn parses_dag_parents_and_maps_missing_height() {
            // A verbose selected-chain block carries a `parents` array of DAG
            // parent hashes (BlockDAG); parse_block_parents returns them raw.
            let json = format!(
                r#"{{"result":{{"hash":"{h}","height":411359,"parents":["{p1}","{p2}"],"tx_count":1,"transactions":[]}}}}"#,
                h = "aa".repeat(32),
                p1 = "bb".repeat(32),
                p2 = "cc".repeat(32),
            );
            let v = Json::parse(&json).unwrap();
            let result = v.get("result").unwrap();
            let parents = parse_block_parents(result, 411359).unwrap();
            assert_eq!(parents, vec![[0xBB; 32], [0xCC; 32]]);

            // No `parents` field (or empty) is a genesis-shaped block, not an
            // error: an empty vector.
            let g = Json::parse(&format!(r#"{{"hash":"{h}","height":0}}"#, h = "dd".repeat(32)))
                .unwrap();
            assert_eq!(parse_block_parents(&g, 0).unwrap(), Vec::<BlockHash>::new());

            // The in-`result` error quirk (no `hash`) maps to HeightNotFound,
            // exactly as the block/hash readers do.
            let err = Json::parse(r#"{"error":"height not found"}"#).unwrap();
            assert_eq!(
                parse_block_parents(&err, 999),
                Err(SourceError::HeightNotFound(999))
            );
        }

        #[test]
        fn url_parsing() {
            let s = HttpBlockSource::new("http://127.0.0.1:8080/").unwrap();
            assert_eq!(s.host, "127.0.0.1");
            assert_eq!(s.port, 8080);
            assert_eq!(s.path, "/");

            let d = HttpBlockSource::new("http://node.example").unwrap();
            assert_eq!(d.host, "node.example");
            assert_eq!(d.port, 16210, "defaults to the node's --rpc-port");
            assert_eq!(d.path, "/");

            assert!(HttpBlockSource::new("https://x").is_err(), "TLS unsupported");
            assert!(HttpBlockSource::new("http://:8080").is_err(), "empty host");
            assert!(HttpBlockSource::new("http://h:notaport").is_err());
        }

        #[test]
        fn never_panics_on_garbage_json() {
            let mut state = 0x1234_5678_9abc_def0u64;
            for len in 0..300usize {
                let mut s = String::new();
                for _ in 0..len {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    s.push((0x20 + (state % 0x5e) as u8) as char);
                }
                let _ = Json::parse(&s); // must not panic
            }
        }

        #[test]
        fn split_http_extracts_status_and_body() {
            let raw = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"result\":1}";
            let (status, body) = split_http(raw).unwrap();
            assert_eq!(status, 200);
            assert_eq!(body, "{\"result\":1}");
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn stx(n: u8) -> SourceTx {
        SourceTx {
            txid: [n; 32],
            tx: Tx { version: 1, inputs: vec![], outputs: vec![], locktime: 0 },
        }
    }

    #[test]
    fn empty_chain_reports_empty() {
        let c = MockChain::new();
        assert_eq!(c.tip_height(), Err(SourceError::EmptyChain));
        assert_eq!(c.block_hash(0), Err(SourceError::HeightNotFound(0)));
        assert_eq!(c.block_by_height(0), Err(SourceError::HeightNotFound(0)));
    }

    #[test]
    fn append_extends_the_selected_chain() {
        let mut c = MockChain::new();
        let h0 = c.append(vec![stx(1)]);
        let h1 = c.append(vec![stx(2)]);
        assert_eq!(c.tip_height(), Ok(1));
        assert_eq!(c.block_hash(0), Ok(h0));
        assert_eq!(c.block_hash(1), Ok(h1));
        assert_ne!(h0, h1);
        let b1 = c.block_by_height(1).unwrap();
        assert_eq!(b1.height, 1);
        assert_eq!(b1.transactions, vec![stx(2)]);
        assert_eq!(c.block_hash(2), Err(SourceError::HeightNotFound(2)));
    }

    #[test]
    fn replace_suffix_forces_a_visible_reorg() {
        let mut c = MockChain::new();
        let h0 = c.append(vec![stx(1)]);
        let h1 = c.append(vec![stx(2)]);
        let h2 = c.append(vec![stx(3)]);

        c.replace_suffix(1, vec![vec![stx(4)], vec![stx(5)], vec![stx(6)]]);
        assert_eq!(c.tip_height(), Ok(3));
        assert_eq!(c.block_hash(0), Ok(h0), "prefix untouched");
        assert_ne!(c.block_hash(1), Ok(h1), "replaced height re-hashes");
        assert_ne!(c.block_hash(2), Ok(h2));

        // Even IDENTICAL transactions re-hash after a reorg (uniq counter).
        let before = c.block_hash(3).unwrap();
        let txs = c.block_by_height(3).unwrap().transactions;
        c.replace_suffix(3, vec![txs]);
        assert_ne!(c.block_hash(3).unwrap(), before);
    }
}
