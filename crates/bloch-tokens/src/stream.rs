//! Chain read access: the [`BlockSource`] trait + [`MockChain`].
//!
//! [`BlockSource`] is shaped **exactly** on the node's documented JSON-RPC
//! surface (`docs/openapi.yaml` in the BlochSISPoW repo — single `POST /`
//! endpoint, JSON-RPC 2.0):
//!
//! | trait method                | JSON-RPC method                       |
//! |-----------------------------|---------------------------------------|
//! | [`BlockSource::tip_height`] | `getblockcount` (tip = count − 1)     |
//! | [`BlockSource::block_hash`] | `getblockhash(height)`                |
//! | [`BlockSource::block_by_height`] | `getblockbyheight(height, verbose=true)` |
//!
//! All three are **reads** — the read RPC is public on every node, which is
//! what keeps the token layer permissionless: anyone can point an indexer at
//! any node (their own included) with no key and no privilege.
//!
//! **A real RPC client is deliberately out of scope for this crate.** No
//! tokio, no HTTP dependency — zero dependencies, offline-buildable. Wiring
//! `BlockSource` to a real node is ~50 lines with any HTTP client: POST
//! `{"jsonrpc":"2.0","method":...,"params":[...],"id":1}` and map the node's
//! non-standard `result.error` quirk (method-level failures arrive inside
//! `result` with HTTP 200) to [`SourceError::HeightNotFound`]. [`MockChain`]
//! stands in for the node so the reference indexer — including its reorg
//! handling — is exercised fully offline and deterministically.
//!
//! Height/DAG note: Bloch is a BlockDAG; `getblockbyheight` serves the
//! node's **selected chain** view, which is what an indexer replays. A reorg
//! (selected-chain change) shows up as `getblockhash(h)` returning a
//! different hash for an already-seen height — exactly what
//! [`crate::indexer::Indexer::sync`] detects. [`MockChain::replace_suffix`]
//! forces that situation in tests.

use crate::chain::ChainTx;

/// A block hash (`Hex32` in openapi.yaml), as raw bytes.
pub type BlockHash = [u8; 32];

/// Read-path failure. `HeightNotFound` mirrors the node's non-standard
/// `result.error` on `getblockhash`/`getblockbyheight`; `EmptyChain` is
/// `getblockcount == 0` (no tip yet); `Transport` is reserved for real
/// clients (network/serialization) and misbehaving sources.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceError {
    EmptyChain,
    HeightNotFound(u64),
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

/// The selected-chain view of one block: the subset of the node's `Block`
/// schema (openapi.yaml, `verbose=true`) that the token layer reads — hash,
/// height, and full transactions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub hash: BlockHash,
    pub height: u64,
    pub transactions: Vec<ChainTx>,
}

/// Read-only access to the selected chain, shaped on the documented node
/// RPC (see module docs for the method mapping). Implemented by
/// [`MockChain`] here; a real JSON-RPC client is out of scope by design.
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

/// In-memory stand-in for the node's read RPC: an append-only selected
/// chain (heights start at 0) that can also be **forced to reorg** by
/// replacing a suffix of blocks ([`MockChain::replace_suffix`]).
///
/// Block hashes are produced by a deterministic mixing function (FNV-1a
/// lanes) over `(height, parent hash, txids, uniq)` — **not cryptographic,
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
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of blocks (== `getblockcount`).
    pub fn block_count(&self) -> u64 {
        self.blocks.len() as u64
    }

    /// Append a block at the next height; returns its hash.
    pub fn append(&mut self, transactions: Vec<ChainTx>) -> BlockHash {
        let height = self.blocks.len() as u64;
        let parent = self.blocks.last().map(|b| b.hash).unwrap_or([0u8; 32]);
        self.uniq += 1;
        let hash = mock_block_hash(height, &parent, &transactions, self.uniq);
        self.blocks.push(Block { hash, height, transactions });
        hash
    }

    /// Force a reorg: drop every block at height >= `from_height`, then
    /// append the replacement blocks in order. The `uniq` counter never
    /// resets, so replacement blocks hash differently from the ones they
    /// replace — an indexer sees a hash mismatch at `from_height`.
    pub fn replace_suffix(&mut self, from_height: u64, replacement: Vec<Vec<ChainTx>>) {
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
fn mock_block_hash(height: u64, parent: &BlockHash, txs: &[ChainTx], uniq: u64) -> BlockHash {
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

// ── Live JSON-RPC client (optional) ─────────────────────────────────────────
//
// A REAL [`BlockSource`] over the node's documented JSON-RPC surface, behind
// the off-by-default `rpc-client` feature. The core crate stays zero-dep and
// offline-buildable; only this seam pulls in `serde_json` (JSON parsing) and
// talks a plain-HTTP `POST /` to the node over `std::net::TcpStream` (no async
// runtime, no HTTP crate). Everything here is READS — see the module docs for
// the method mapping. Still just ONE indexer among many; unaudited.
#[cfg(feature = "rpc-client")]
pub mod rpc {
    use super::{Block, BlockHash, BlockSource, SourceError};
    use crate::chain::{ChainTx, OutPoint};
    use crate::envelope::TxOut;
    use std::cell::Cell;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    /// Live read-only client for a Bloch node's JSON-RPC (`POST /`, JSON-RPC
    /// 2.0). Construct with [`RpcBlockSource::new`] (`"127.0.0.1:16210"`), then
    /// hand it to [`crate::indexer::Indexer::sync`] exactly like [`super::MockChain`].
    ///
    /// Permissionless by construction: the three methods it calls
    /// (`getblockcount`, `getblockhash`, `getblockbyheight`) are the public
    /// reads on every node — no key, no privilege. Zero consensus change.
    pub struct RpcBlockSource {
        host: String,
        port: u16,
        id: Cell<u64>,
        timeout: Duration,
    }

    impl RpcBlockSource {
        /// `endpoint` is `"host:port"` (e.g. `"127.0.0.1:16210"`). A bare host
        /// defaults to port 16210 (the node's documented default).
        pub fn new(endpoint: &str) -> Result<Self, SourceError> {
            let (host, port) = match endpoint.rsplit_once(':') {
                Some((h, p)) => (
                    h.to_string(),
                    p.parse::<u16>()
                        .map_err(|_| SourceError::Transport(format!("bad port in {endpoint:?}")))?,
                ),
                None => (endpoint.to_string(), 16210),
            };
            if host.is_empty() {
                return Err(SourceError::Transport(format!("empty host in {endpoint:?}")));
            }
            Ok(Self { host, port, id: Cell::new(0), timeout: Duration::from_secs(30) })
        }

        /// Override the per-request read timeout (default 30s).
        pub fn with_timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self
        }

        /// One JSON-RPC round trip. Returns the `result` value. A top-level
        /// JSON-RPC `error` (auth/rate-limit, HTTP 401/429) is a transport
        /// failure. The node's NON-STANDARD method-level failure — a `result`
        /// that is instead `{"error": "..."}` with HTTP 200 — is returned
        /// as-is here and classified by the caller (height-lookups treat it as
        /// [`SourceError::HeightNotFound`]).
        fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, SourceError> {
            let id = self.id.get().wrapping_add(1);
            self.id.set(id);
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": method,
                "params": params,
            })
            .to_string();

            let addr = format!("{}:{}", self.host, self.port);
            let mut stream = TcpStream::connect(&addr)
                .map_err(|e| SourceError::Transport(format!("connect {addr}: {e}")))?;
            stream
                .set_read_timeout(Some(self.timeout))
                .map_err(|e| SourceError::Transport(e.to_string()))?;

            let request = format!(
                "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(request.as_bytes())
                .map_err(|e| SourceError::Transport(format!("write {method}: {e}")))?;
            stream.flush().map_err(|e| SourceError::Transport(e.to_string()))?;

            let mut raw = Vec::new();
            stream
                .read_to_end(&mut raw)
                .map_err(|e| SourceError::Transport(format!("read {method}: {e}")))?;
            let text = String::from_utf8_lossy(&raw);

            // Split HTTP headers from body; de-chunk if chunked.
            let start = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
            let body_text = &text[start..];
            let json = if text.contains("Transfer-Encoding: chunked") {
                dechunk(body_text)
            } else {
                body_text.trim().to_string()
            };

            let resp: serde_json::Value = serde_json::from_str(&json)
                .map_err(|e| SourceError::Transport(format!("{method}: invalid JSON: {e}")))?;

            // Top-level JSON-RPC error object (auth / rate-limit / malformed).
            if let Some(err) = resp.get("error") {
                if !err.is_null() {
                    return Err(SourceError::Transport(format!("{method}: rpc error: {err}")));
                }
            }
            Ok(resp.get("result").cloned().unwrap_or(resp))
        }
    }

    /// `true` when `result` is the node's method-level failure sentinel
    /// (`{"error": "..."}` returned with HTTP 200 instead of a real result).
    fn is_method_error(v: &serde_json::Value) -> bool {
        v.get("error").map(|e| !e.is_null()).unwrap_or(false)
    }

    /// Decode a JSON hex string into a fixed 32-byte array.
    fn parse_hash32(v: &serde_json::Value, what: &str) -> Result<[u8; 32], SourceError> {
        let s = v
            .as_str()
            .ok_or_else(|| SourceError::Transport(format!("{what}: expected hex string")))?;
        let bytes = hex_decode(s)
            .ok_or_else(|| SourceError::Transport(format!("{what}: invalid hex {s:?}")))?;
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| SourceError::Transport(format!("{what}: expected 32 bytes, got {} hex", s.len())))
    }

    /// Minimal, dependency-free hex decoder (even length, `0-9a-fA-F`).
    fn hex_decode(s: &str) -> Option<Vec<u8>> {
        let b = s.as_bytes();
        if b.len() % 2 != 0 {
            return None;
        }
        let nib = |c: u8| -> Option<u8> {
            match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                b'A'..=b'F' => Some(c - b'A' + 10),
                _ => None,
            }
        };
        let mut out = Vec::with_capacity(b.len() / 2);
        for pair in b.chunks_exact(2) {
            out.push((nib(pair[0])? << 4) | nib(pair[1])?);
        }
        Some(out)
    }

    /// De-chunk an HTTP/1.1 `Transfer-Encoding: chunked` body.
    fn dechunk(body: &str) -> String {
        let mut out = String::new();
        let mut rem = body.trim();
        loop {
            let nl = match rem.find("\r\n") {
                Some(i) => i,
                None => break,
            };
            let size = match usize::from_str_radix(rem[..nl].trim(), 16) {
                Ok(0) => break,
                Ok(s) => s,
                Err(_) => return body.trim().to_string(),
            };
            rem = &rem[nl + 2..];
            if rem.len() < size {
                break;
            }
            out.push_str(&rem[..size]);
            rem = &rem[size..];
            if rem.starts_with("\r\n") {
                rem = &rem[2..];
            }
        }
        if out.is_empty() {
            body.trim().to_string()
        } else {
            out
        }
    }

    /// Map the node's verbose `transactions[]` JSON (see the node's `format_tx`)
    /// into the token layer's [`ChainTx`] read model — txid, spent outpoints,
    /// and `(value, script_pubkey)` outputs. BLCH values pass through untouched
    /// (the token layer reads them only to enforce the zero-value envelope rule).
    fn parse_tx(v: &serde_json::Value) -> Result<ChainTx, SourceError> {
        let txid = parse_hash32(&v["txid"], "tx.txid")?;

        let inputs = match v.get("inputs").and_then(|x| x.as_array()) {
            Some(arr) => {
                let mut ins = Vec::with_capacity(arr.len());
                for i in arr {
                    ins.push(OutPoint {
                        txid: parse_hash32(&i["prev_txid"], "input.prev_txid")?,
                        vout: i["prev_index"]
                            .as_u64()
                            .ok_or_else(|| SourceError::Transport("input.prev_index missing".into()))?
                            as u32,
                    });
                }
                ins
            }
            None => Vec::new(),
        };

        let outputs = match v.get("outputs").and_then(|x| x.as_array()) {
            Some(arr) => {
                let mut outs = Vec::with_capacity(arr.len());
                for o in arr {
                    let value = o["value"]
                        .as_u64()
                        .ok_or_else(|| SourceError::Transport("output.value missing".into()))?;
                    let spk_hex = o["script_pubkey"]
                        .as_str()
                        .ok_or_else(|| SourceError::Transport("output.script_pubkey missing".into()))?;
                    let script_pubkey = hex_decode(spk_hex).ok_or_else(|| {
                        SourceError::Transport(format!("output.script_pubkey invalid hex {spk_hex:?}"))
                    })?;
                    outs.push(TxOut { value, script_pubkey });
                }
                outs
            }
            None => Vec::new(),
        };

        Ok(ChainTx { txid, inputs, outputs })
    }

    impl BlockSource for RpcBlockSource {
        fn tip_height(&self) -> Result<u64, SourceError> {
            let result = self.call("getblockcount", serde_json::json!([]))?;
            let count = result
                .as_u64()
                .ok_or_else(|| SourceError::Transport(format!("getblockcount: not a number: {result}")))?;
            match count {
                0 => Err(SourceError::EmptyChain),
                n => Ok(n - 1),
            }
        }

        fn block_hash(&self, height: u64) -> Result<BlockHash, SourceError> {
            let result = self.call("getblockhash", serde_json::json!([height]))?;
            if is_method_error(&result) {
                return Err(SourceError::HeightNotFound(height));
            }
            parse_hash32(&result, "getblockhash")
        }

        fn block_by_height(&self, height: u64) -> Result<Block, SourceError> {
            let result = self.call("getblockbyheight", serde_json::json!([height, true]))?;
            if is_method_error(&result) {
                return Err(SourceError::HeightNotFound(height));
            }
            let hash = parse_hash32(&result["hash"], "block.hash")?;
            let block_height = result["height"]
                .as_u64()
                .ok_or_else(|| SourceError::Transport("block.height missing".into()))?;
            let transactions = match result.get("transactions").and_then(|t| t.as_array()) {
                Some(arr) => {
                    let mut txs = Vec::with_capacity(arr.len());
                    for t in arr {
                        txs.push(parse_tx(t)?);
                    }
                    txs
                }
                None => {
                    return Err(SourceError::Transport(
                        "getblockbyheight: no transactions[] (verbose=true required)".into(),
                    ))
                }
            };
            Ok(Block { hash, height: block_height, transactions })
        }
    }

    #[cfg(test)]
    mod rpc_tests {
        use super::*;

        #[test]
        fn hex_decode_roundtrip_and_rejects() {
            assert_eq!(hex_decode("00ff10"), Some(vec![0x00, 0xff, 0x10]));
            assert_eq!(hex_decode(""), Some(vec![]));
            assert_eq!(hex_decode("0"), None, "odd length");
            assert_eq!(hex_decode("zz"), None, "non-hex");
        }

        #[test]
        fn dechunk_reassembles_body() {
            // "TKV0" split across two chunks, then the terminal 0-chunk.
            let chunked = "2\r\nTK\r\n2\r\nV0\r\n0\r\n\r\n";
            assert_eq!(dechunk(chunked), "TKV0");
        }

        #[test]
        fn parse_tx_maps_inputs_and_outputs() {
            let v = serde_json::json!({
                "txid": "00".repeat(32),
                "inputs": [{ "prev_txid": "11".repeat(32), "prev_index": 3 }],
                "outputs": [
                    { "value": 546, "script_pubkey": "aabb" },
                    { "value": 0, "script_pubkey": "544b5630" }
                ],
            });
            let tx = parse_tx(&v).unwrap();
            assert_eq!(tx.txid, [0u8; 32]);
            assert_eq!(tx.inputs, vec![OutPoint { txid: [0x11; 32], vout: 3 }]);
            assert_eq!(tx.outputs.len(), 2);
            assert_eq!(tx.outputs[0], TxOut { value: 546, script_pubkey: vec![0xaa, 0xbb] });
            assert_eq!(tx.outputs[1].value, 0);
            assert_eq!(tx.outputs[1].script_pubkey, b"TKV0");
        }

        #[test]
        fn method_error_sentinel_detected() {
            assert!(is_method_error(&serde_json::json!({ "error": "height not found" })));
            assert!(!is_method_error(&serde_json::json!("deadbeef")));
            assert!(!is_method_error(&serde_json::json!({ "hash": "00" })));
        }

        #[test]
        fn endpoint_parsing() {
            let s = RpcBlockSource::new("127.0.0.1:16210").unwrap();
            assert_eq!(s.host, "127.0.0.1");
            assert_eq!(s.port, 16210);
            let d = RpcBlockSource::new("node.example").unwrap();
            assert_eq!(d.port, 16210, "bare host defaults to 16210");
            assert!(RpcBlockSource::new(":99").is_err(), "empty host");
            assert!(RpcBlockSource::new("h:notaport").is_err(), "bad port");
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tx(n: u8) -> ChainTx {
        ChainTx { txid: [n; 32], inputs: vec![], outputs: vec![] }
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
        let h0 = c.append(vec![tx(1)]);
        let h1 = c.append(vec![tx(2)]);
        assert_eq!(c.tip_height(), Ok(1));
        assert_eq!(c.block_hash(0), Ok(h0));
        assert_eq!(c.block_hash(1), Ok(h1));
        assert_ne!(h0, h1);
        let b1 = c.block_by_height(1).unwrap();
        assert_eq!(b1.height, 1);
        assert_eq!(b1.transactions, vec![tx(2)]);
        assert_eq!(c.block_hash(2), Err(SourceError::HeightNotFound(2)));
    }

    #[test]
    fn replace_suffix_forces_a_visible_reorg() {
        let mut c = MockChain::new();
        let h0 = c.append(vec![tx(1)]);
        let h1 = c.append(vec![tx(2)]);
        let h2 = c.append(vec![tx(3)]);

        // Replace heights 1.. with a different (longer) branch.
        c.replace_suffix(1, vec![vec![tx(4)], vec![tx(5)], vec![tx(6)]]);
        assert_eq!(c.tip_height(), Ok(3));
        assert_eq!(c.block_hash(0), Ok(h0), "prefix untouched");
        assert_ne!(c.block_hash(1), Ok(h1), "replaced height re-hashes");
        assert_ne!(c.block_hash(2), Ok(h2));

        // Even IDENTICAL transactions re-hash after a reorg (uniq counter):
        // a same-height same-txs replacement is still a visible new block.
        let before = c.block_hash(3).unwrap();
        let txs = c.block_by_height(3).unwrap().transactions;
        c.replace_suffix(3, vec![txs]);
        assert_ne!(c.block_hash(3).unwrap(), before);
    }

    #[test]
    fn mock_hash_is_deterministic_and_input_sensitive() {
        let parent = [7u8; 32];
        let a = mock_block_hash(3, &parent, &[tx(1)], 9);
        assert_eq!(a, mock_block_hash(3, &parent, &[tx(1)], 9));
        assert_ne!(a, mock_block_hash(4, &parent, &[tx(1)], 9));
        assert_ne!(a, mock_block_hash(3, &[8u8; 32], &[tx(1)], 9));
        assert_ne!(a, mock_block_hash(3, &parent, &[tx(2)], 9));
        assert_ne!(a, mock_block_hash(3, &parent, &[tx(1)], 10));
    }
}
