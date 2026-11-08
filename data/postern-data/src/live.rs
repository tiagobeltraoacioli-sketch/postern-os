//! REAL hosted-provider `StorageBackend` — the Lighthouse client.
//!
//! Spec: `docs/specs/POSTERN-DATA-FILECOIN-DESIGN.md`, §4 ("`LighthouseBackend`
//! — the MVP live impl"). This is the one place in the crate that actually
//! touches the network. It is gated behind the `live` cargo feature so the
//! default build stays offline and network-incapable (the structural honesty
//! gate); everything above the [`crate::backend::StorageBackend`] seam remains
//! deterministic, panic-free, and offline-testable.
//!
//! # Why Lighthouse
//!
//! Of the two hosted deal-making providers in the spec, Lighthouse is the MVP
//! choice because it is **pure-Rust-reachable with a shared-bearer HTTP API**:
//! a single `POST .../api/v0/add` (multipart, `Authorization: Bearer <key>`)
//! returns `{"Hash": "<cid>"}`, retrieval is a plain gateway `GET`, and
//! persistence is a `GET .../deal_status?cid=`. Storacha's UCAN model has
//! better auth but its SDK is JavaScript and needs a Node sidecar — exactly the
//! moving part an MVP defers. So: Lighthouse now, the trait keeps Storacha
//! addable later.
//!
//! # Honesty rails (non-negotiable)
//!
//! * **Ciphertext only.** Data is Postern-SEALED (XChaCha20-Poly1305 v2,
//!   Argon2id) BEFORE it reaches any backend. Lighthouse, its Filecoin SPs,
//!   gateways, and anyone holding the CID see **ciphertext only**. Using a
//!   provider means trusting it for *availability*, never *confidentiality*.
//! * **The CID is a locator, not a proof.** The returned [`Cid`] is
//!   provider-reported and carries ZERO integrity weight. The caller MUST
//!   re-verify a SHAKE-256 digest (the DATA0 anchor's commitment) against the
//!   manifest after every [`get`](LiveBackend::get) — this crate cannot (it has
//!   no hashing).
//! * **Reference prototype, UNAUDITED. Zero-value testnet.** The bearer key on
//!   the box grants upload/quota abuse, NOT data access.
//!
//! # Zero dependencies, even when live
//!
//! The HTTP/1.1 client is hand-rolled over `std::net::TcpStream`, so enabling
//! `live` adds **no external crates** — matching the crate's zero-dep ethos.
//! The trade-off: **TLS is not linked in-crate.** The default endpoints point at
//! the real HTTPS Lighthouse hosts, but this plaintext client cannot terminate
//! TLS. To go live against the real hosts, front them with a local
//! TLS-terminating proxy (`stunnel`/`socat` to `node.lighthouse.storage:443`)
//! and set the `LIGHTHOUSE_*_URL` env overrides to the `http://127.0.0.1:<port>`
//! proxy — the same local-egress model the spec's Tor-SOCKS rail already
//! assumes. `https://` targets are rejected with a typed error rather than
//! silently failing.

use crate::backend::{BackendError, Cid, DealInfo, DealStatus, StorageBackend};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Default Lighthouse upload endpoint (multipart `add`). HTTPS — reachable only
/// through a local TLS proxy (see module docs); override via
/// `LIGHTHOUSE_UPLOAD_URL`.
pub const DEFAULT_UPLOAD_URL: &str = "https://node.lighthouse.storage/api/v0/add";
/// Default Lighthouse retrieval gateway base (the CID is appended as `/<cid>`).
/// Override via `LIGHTHOUSE_GATEWAY_URL`.
pub const DEFAULT_GATEWAY_URL: &str = "https://gateway.lighthouse.storage/ipfs";
/// Default Lighthouse deal-status endpoint (`?cid=<cid>` is appended). Override
/// via `LIGHTHOUSE_DEAL_STATUS_URL`.
pub const DEFAULT_DEAL_STATUS_URL: &str = "https://api.lighthouse.storage/api/lighthouse/deal_status";
/// Env var carrying the Lighthouse API key (Bearer token). REQUIRED for the
/// live client; no key ⇒ [`LiveBackend::from_env`] refuses to build.
pub const ENV_API_KEY: &str = "LIGHTHOUSE_API_KEY";
/// Env override for [`DEFAULT_UPLOAD_URL`].
pub const ENV_UPLOAD_URL: &str = "LIGHTHOUSE_UPLOAD_URL";
/// Env override for [`DEFAULT_GATEWAY_URL`].
pub const ENV_GATEWAY_URL: &str = "LIGHTHOUSE_GATEWAY_URL";
/// Env override for [`DEFAULT_DEAL_STATUS_URL`].
pub const ENV_DEAL_STATUS_URL: &str = "LIGHTHOUSE_DEAL_STATUS_URL";

/// Multipart boundary for the `add` upload body. Fixed; any value the body
/// never contains is valid, and ciphertext-vs-boundary collision is astronomically
/// unlikely for this ASCII token.
const MULTIPART_BOUNDARY: &str = "----PosternDataBoundaryqm7MA4YWxkTrZu0gW";

/// Configuration for the live Lighthouse [`LiveBackend`].
#[derive(Clone, Debug)]
pub struct LiveConfig {
    /// Lighthouse API key (sent as `Authorization: Bearer <key>`).
    pub api_key: String,
    /// Upload endpoint (`POST`, multipart). Defaults to [`DEFAULT_UPLOAD_URL`].
    pub upload_url: String,
    /// Retrieval gateway base; the CID is appended as `/<cid>`. Defaults to
    /// [`DEFAULT_GATEWAY_URL`].
    pub gateway_url: String,
    /// Deal-status endpoint; `?cid=<cid>` is appended. Defaults to
    /// [`DEFAULT_DEAL_STATUS_URL`].
    pub deal_status_url: String,
    /// Connect + read + write timeout for every request. Defaults to 30s.
    pub timeout: Duration,
}

impl LiveConfig {
    /// A config with the real Lighthouse endpoints and the given key.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            upload_url: DEFAULT_UPLOAD_URL.to_string(),
            gateway_url: DEFAULT_GATEWAY_URL.to_string(),
            deal_status_url: DEFAULT_DEAL_STATUS_URL.to_string(),
            timeout: Duration::from_secs(30),
        }
    }
}

/// The REAL live Lighthouse backend.
///
/// Construct it from the environment with [`LiveBackend::from_env`] (the
/// intended path — it refuses to build without a `LIGHTHOUSE_API_KEY`), or
/// directly from a [`LiveConfig`] with [`LiveBackend::new`].
#[derive(Clone, Debug)]
pub struct LiveBackend {
    config: LiveConfig,
}

impl LiveBackend {
    /// Build from an explicit [`LiveConfig`].
    pub fn new(config: LiveConfig) -> Self {
        Self { config }
    }

    /// Build from the environment. Requires [`ENV_API_KEY`]; honours the
    /// `LIGHTHOUSE_*_URL` overrides (falling back to the real Lighthouse hosts).
    ///
    /// Returns [`BackendError::Unavailable`] if no API key is set — this is the
    /// "no token found" branch: without a key there is nothing honest to do.
    pub fn from_env() -> Result<Self, BackendError> {
        let api_key = std::env::var(ENV_API_KEY).map_err(|_| {
            BackendError::Unavailable(format!(
                "no Lighthouse API key: set {ENV_API_KEY} to enable live uploads"
            ))
        })?;
        if api_key.trim().is_empty() {
            return Err(BackendError::Unavailable(format!("{ENV_API_KEY} is empty")));
        }
        let env_or = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
        Ok(Self::new(LiveConfig {
            api_key,
            upload_url: env_or(ENV_UPLOAD_URL, DEFAULT_UPLOAD_URL),
            gateway_url: env_or(ENV_GATEWAY_URL, DEFAULT_GATEWAY_URL),
            deal_status_url: env_or(ENV_DEAL_STATUS_URL, DEFAULT_DEAL_STATUS_URL),
            timeout: Duration::from_secs(30),
        }))
    }

    /// Borrow the config (handy for tests / diagnostics).
    pub fn config(&self) -> &LiveConfig {
        &self.config
    }
}

impl StorageBackend for LiveBackend {
    /// Upload the opaque (already-sealed) ciphertext CAR to Lighthouse and
    /// return the provider-reported CID as a LOCATOR (zero integrity weight).
    ///
    /// `POST <upload_url>` as `multipart/form-data` with an `Authorization:
    /// Bearer <key>` header; the response JSON's `Hash` field is the CID. The
    /// CID string is stored verbatim as the [`Cid`] bytes (this crate treats a
    /// CID as opaque), which is exactly what [`get`](Self::get) needs to fetch
    /// it back from the gateway.
    fn put_car(&mut self, bytes: &[u8]) -> Result<Cid, BackendError> {
        let url = Url::parse(&self.config.upload_url)?;
        let body = multipart_body(bytes);
        let headers = [
            ("Authorization", format!("Bearer {}", self.config.api_key)),
            (
                "Content-Type",
                format!("multipart/form-data; boundary={MULTIPART_BOUNDARY}"),
            ),
        ];
        let resp = http_request("POST", &url, &headers, Some(&body), self.config.timeout)?;
        if resp.status != 200 {
            return Err(BackendError::Unavailable(format!(
                "lighthouse add returned HTTP {}: {}",
                resp.status,
                truncate_for_msg(&resp.body)
            )));
        }
        let cid = extract_json_string(&resp.body, "Hash").ok_or_else(|| {
            BackendError::Unavailable(format!(
                "lighthouse add response missing \"Hash\": {}",
                truncate_for_msg(&resp.body)
            ))
        })?;
        if cid.is_empty() {
            return Err(BackendError::Unavailable(
                "lighthouse add returned an empty CID".to_string(),
            ));
        }
        Ok(Cid(cid.into_bytes()))
    }

    /// Fetch the bytes stored under `cid` from the retrieval gateway.
    ///
    /// `GET <gateway_url>/<cid>`. The returned bytes are UNTRUSTED — the caller
    /// MUST re-verify the manifest's SHAKE-256 digest before use. A 404 maps to
    /// [`BackendError::NotFound`]; other non-2xx to
    /// [`BackendError::Unavailable`].
    fn get(&mut self, cid: &Cid) -> Result<Vec<u8>, BackendError> {
        let cid_str = cid_to_str(cid)?;
        let full = format!("{}/{}", self.config.gateway_url.trim_end_matches('/'), cid_str);
        let url = Url::parse(&full)?;
        let resp = http_request("GET", &url, &[], None, self.config.timeout)?;
        match resp.status {
            200 => Ok(resp.body),
            404 => Err(BackendError::NotFound),
            other => Err(BackendError::Unavailable(format!(
                "lighthouse gateway GET returned HTTP {other}"
            ))),
        }
    }

    /// Persistence probe (§6 vocabulary). `GET <deal_status_url>?cid=<cid>`.
    ///
    /// Honest mapping: on-chain deals present ⇒ [`DealStatus::DealActive`]; the
    /// provider answers 200 but reports no deals yet ⇒
    /// [`DealStatus::Acknowledged`] (HOT layer only — NOT a deal); unreachable
    /// or no record ⇒ [`DealStatus::Unknown`]. Deal parsing is best-effort over
    /// the JSON array (locator-only data).
    fn deal_status(&mut self, cid: &Cid) -> Result<DealStatus, BackendError> {
        let cid_str = cid_to_str(cid)?;
        let sep = if self.config.deal_status_url.contains('?') { '&' } else { '?' };
        let full = format!("{}{}cid={}", self.config.deal_status_url, sep, cid_str);
        let url = Url::parse(&full)?;
        let resp = match http_request("GET", &url, &[], None, self.config.timeout) {
            Ok(r) => r,
            // Transport failure is not a NotFound — it is honestly Unknown.
            Err(BackendError::Unavailable(_)) => return Ok(DealStatus::Unknown),
            Err(e) => return Err(e),
        };
        if resp.status == 404 {
            return Ok(DealStatus::Unknown);
        }
        if resp.status != 200 {
            return Ok(DealStatus::Unknown);
        }
        let deals = parse_deals(&resp.body);
        if deals.is_empty() {
            // 200 with no deals: provider claims the bytes but there is no deal.
            Ok(DealStatus::Acknowledged)
        } else {
            Ok(DealStatus::DealActive(deals))
        }
    }
}

// ── CID <-> string ─────────────────────────────────────────────────────────────

/// The live [`Cid`] holds the provider's CID **string** as UTF-8 bytes (that is
/// what Lighthouse returns and what the gateway path needs). Non-UTF-8 locator
/// bytes cannot address a gateway path and are rejected.
fn cid_to_str(cid: &Cid) -> Result<String, BackendError> {
    std::str::from_utf8(cid.as_bytes())
        .map(str::to_string)
        .map_err(|_| BackendError::Unavailable("cid is not a valid UTF-8 locator".to_string()))
}

// ── Minimal URL parsing (http:// only; https:// rejected with guidance) ─────────

#[derive(Debug)]
struct Url {
    host: String,
    port: u16,
    /// Path + optional query, always beginning with `/`.
    target: String,
}

impl Url {
    fn parse(input: &str) -> Result<Url, BackendError> {
        if let Some(rest) = input.strip_prefix("https://") {
            let _ = rest;
            return Err(BackendError::Unavailable(format!(
                "https not supported in-crate (no TLS linked): front `{input}` with a local \
                 TLS-terminating proxy and set the LIGHTHOUSE_*_URL env override to its \
                 http://127.0.0.1:<port> address"
            )));
        }
        let rest = input.strip_prefix("http://").ok_or_else(|| {
            BackendError::Unavailable(format!("unsupported URL scheme: {input}"))
        })?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => {
                let port = p.parse::<u16>().map_err(|_| {
                    BackendError::Unavailable(format!("bad port in URL: {input}"))
                })?;
                (h.to_string(), port)
            }
            None => (authority.to_string(), 80),
        };
        if host.is_empty() {
            return Err(BackendError::Unavailable(format!("empty host in URL: {input}")));
        }
        Ok(Url { host, port, target: path.to_string() })
    }
}

// ── Hand-rolled HTTP/1.1 over TcpStream ─────────────────────────────────────────

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

/// Perform one blocking HTTP/1.1 request with connect/read/write timeouts.
/// Transport / protocol failures map to [`BackendError::Unavailable`].
fn http_request(
    method: &str,
    url: &Url,
    headers: &[(&str, String)],
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<HttpResponse, BackendError> {
    let addr = (url.host.as_str(), url.port)
        .to_socket_addrs()
        .map_err(|e| BackendError::Unavailable(format!("resolve {}: {e}", url.host)))?
        .next()
        .ok_or_else(|| BackendError::Unavailable(format!("no address for {}", url.host)))?;

    let mut stream = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|e| BackendError::Unavailable(format!("connect {addr}: {e}")))?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|_| stream.set_write_timeout(Some(timeout)))
        .map_err(|e| BackendError::Unavailable(format!("set timeout: {e}")))?;

    let mut req = Vec::new();
    req.extend_from_slice(
        format!("{method} {} HTTP/1.1\r\n", url.target).as_bytes(),
    );
    req.extend_from_slice(format!("Host: {}\r\n", url.host).as_bytes());
    req.extend_from_slice(b"Connection: close\r\n");
    req.extend_from_slice(b"Accept: */*\r\n");
    for (k, v) in headers {
        req.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    let body = body.unwrap_or(&[]);
    req.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    req.extend_from_slice(b"\r\n");
    req.extend_from_slice(body);

    stream
        .write_all(&req)
        .map_err(|e| BackendError::Unavailable(format!("write request: {e}")))?;
    stream
        .flush()
        .map_err(|e| BackendError::Unavailable(format!("flush: {e}")))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| BackendError::Unavailable(format!("read response: {e}")))?;

    parse_http_response(&raw)
}

/// Parse a raw HTTP/1.1 response: status line + headers + body, decoding
/// `Transfer-Encoding: chunked` when present, else honouring `Content-Length`,
/// else taking the remainder (valid because we send `Connection: close`).
fn parse_http_response(raw: &[u8]) -> Result<HttpResponse, BackendError> {
    let split = find_subslice(raw, b"\r\n\r\n")
        .ok_or_else(|| BackendError::Unavailable("malformed HTTP response (no header end)".into()))?;
    let head = &raw[..split];
    let mut body = &raw[split + 4..];

    let head_str = String::from_utf8_lossy(head);
    let mut lines = head_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| BackendError::Unavailable("empty HTTP response".into()))?;
    // "HTTP/1.1 200 OK"
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| {
            BackendError::Unavailable(format!("bad HTTP status line: {status_line}"))
        })?;

    let mut chunked = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            if k == "transfer-encoding" && v.eq_ignore_ascii_case("chunked") {
                chunked = true;
            }
        }
    }

    let decoded;
    if chunked {
        decoded = decode_chunked(body)?;
        body = &decoded;
    }

    Ok(HttpResponse { status, body: body.to_vec() })
}

/// Decode an HTTP/1.1 chunked body.
fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>, BackendError> {
    let mut out = Vec::new();
    loop {
        let nl = find_subslice(input, b"\r\n")
            .ok_or_else(|| BackendError::Unavailable("chunked: missing size CRLF".into()))?;
        let size_line = String::from_utf8_lossy(&input[..nl]);
        // Ignore any chunk extensions after ';'.
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| BackendError::Unavailable(format!("chunked: bad size {size_hex:?}")))?;
        input = &input[nl + 2..];
        if size == 0 {
            break;
        }
        if input.len() < size {
            return Err(BackendError::Unavailable("chunked: short chunk".into()));
        }
        out.extend_from_slice(&input[..size]);
        input = &input[size..];
        // Trailing CRLF after each chunk.
        if input.starts_with(b"\r\n") {
            input = &input[2..];
        }
    }
    Ok(out)
}

// ── Multipart + minimal JSON scanning ───────────────────────────────────────────

/// Encode `bytes` as a single `multipart/form-data` file part named `file`.
fn multipart_body(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(format!("--{MULTIPART_BOUNDARY}\r\n").as_bytes());
    out.extend_from_slice(
        b"Content-Disposition: form-data; name=\"file\"; filename=\"blob\"\r\n",
    );
    out.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    out.extend_from_slice(bytes);
    out.extend_from_slice(format!("\r\n--{MULTIPART_BOUNDARY}--\r\n").as_bytes());
    out
}

/// Extract the string value of top-level-ish JSON key `key` from `body`
/// (`"key"` then `:` then a `"…"` string). Minimal and tolerant — good enough
/// for Lighthouse's flat `{"Name":…,"Hash":…,"Size":…}` shape; this crate does
/// not pull a JSON parser.
fn extract_json_string(body: &[u8], key: &str) -> Option<String> {
    let s = std::str::from_utf8(body).ok()?;
    let needle = format!("\"{key}\"");
    let mut idx = s.find(&needle)? + needle.len();
    let bytes = s.as_bytes();
    // skip whitespace + ':'
    while idx < bytes.len() && (bytes[idx] as char).is_whitespace() {
        idx += 1;
    }
    if idx >= bytes.len() || bytes[idx] != b':' {
        return None;
    }
    idx += 1;
    while idx < bytes.len() && (bytes[idx] as char).is_whitespace() {
        idx += 1;
    }
    if idx >= bytes.len() || bytes[idx] != b'"' {
        return None;
    }
    idx += 1;
    let start = idx;
    while idx < bytes.len() && bytes[idx] != b'"' {
        // no escape handling needed for CID/base32/base58 values
        idx += 1;
    }
    Some(s[start..idx].to_string())
}

/// Extract the integer value of JSON key `key` beginning at/after `from` within
/// `s`, if the value is a number (not `null`).
fn extract_json_int_after(s: &str, key: &str, from: usize) -> Option<u64> {
    let needle = format!("\"{key}\"");
    let rel = s[from..].find(&needle)? + from + needle.len();
    let bytes = s.as_bytes();
    let mut idx = rel;
    while idx < bytes.len() && (bytes[idx] == b':' || (bytes[idx] as char).is_whitespace()) {
        idx += 1;
    }
    let start = idx;
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    if idx == start {
        return None;
    }
    s[start..idx].parse::<u64>().ok()
}

/// Best-effort parse of a Lighthouse `deal_status` JSON array into
/// [`DealInfo`]s. Splits the array into object-ish segments on `{` and reads
/// `dealId`, `storageProvider`/`provider`, and `expirationEpoch`/`endEpoch`.
/// Locator-only data — never trusted for integrity.
fn parse_deals(body: &[u8]) -> Vec<DealInfo> {
    let s = match std::str::from_utf8(body) {
        Ok(s) => s.trim(),
        Err(_) => return Vec::new(),
    };
    if s.is_empty() || s == "[]" || s == "null" {
        return Vec::new();
    }
    let mut deals = Vec::new();
    for seg in s.split('{').skip(1) {
        let deal_id = extract_json_int_after(seg, "dealId", 0);
        let end_epoch = extract_json_int_after(seg, "expirationEpoch", 0)
            .or_else(|| extract_json_int_after(seg, "endEpoch", 0))
            .or_else(|| extract_json_int_after(seg, "end_epoch", 0));
        let provider = extract_json_string(seg.as_bytes(), "storageProvider")
            .or_else(|| extract_json_string(seg.as_bytes(), "provider"))
            .unwrap_or_default();
        // Only record a segment that actually looked like a deal.
        if deal_id.is_some() || !provider.is_empty() || end_epoch.is_some() {
            deals.push(DealInfo { deal_id, provider, end_epoch });
        }
    }
    deals
}

// ── small utilities ─────────────────────────────────────────────────────────────

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

fn truncate_for_msg(body: &[u8]) -> String {
    let s = String::from_utf8_lossy(body);
    let s = s.trim();
    if s.len() > 200 {
        format!("{}…", &s[..200])
    } else {
        s.to_string()
    }
}

// ── Tests: mock HTTP server round-trips (always run under --features live) ───────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    /// One captured request the mock server saw.
    struct CapturedRequest {
        request_line: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl CapturedRequest {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }
    }

    /// Read one HTTP request (request line, headers, Content-Length body) from a
    /// stream.
    fn read_request(stream: &TcpStream) -> CapturedRequest {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let request_line = request_line.trim_end().to_string();

        let mut headers = Vec::new();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                let k = k.trim().to_string();
                let v = v.trim().to_string();
                if k.eq_ignore_ascii_case("content-length") {
                    content_length = v.parse().unwrap_or(0);
                }
                headers.push((k, v));
            }
        }
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut body).unwrap();
        }
        CapturedRequest { request_line, headers, body }
    }

    /// Spawn a one-shot mock server that serves `response` (raw bytes,
    /// status+headers+body) for a single connection and hands the captured
    /// request back over a channel. Returns the bound `http://127.0.0.1:port`.
    fn spawn_mock(response: Vec<u8>) -> (String, mpsc::Receiver<CapturedRequest>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let captured = read_request(&stream);
            stream.write_all(&response).unwrap();
            stream.flush().unwrap();
            // Half-close so the client's read_to_end returns.
            let _ = stream.shutdown(std::net::Shutdown::Write);
            let _ = tx.send(captured);
        });
        (format!("http://{addr}"), rx)
    }

    fn http_response(status_line: &str, body: &[u8]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(format!("HTTP/1.1 {status_line}\r\n").as_bytes());
        r.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        r.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        r.extend_from_slice(body);
        r
    }

    fn cfg_for(base: &str) -> LiveConfig {
        LiveConfig {
            api_key: "test-key-abc123".to_string(),
            upload_url: format!("{base}/api/v0/add"),
            gateway_url: format!("{base}/ipfs"),
            deal_status_url: format!("{base}/api/lighthouse/deal_status"),
            timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn put_car_sends_bearer_and_multipart_and_parses_cid() {
        // The sealed ciphertext the caller hands the seam (opaque bytes).
        let sealed = b"SEALED-ciphertext-\x00\x01\x02-not-plaintext";
        let cid_str = "bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy";
        let resp = http_response(
            "200 OK",
            format!("{{\"Name\":\"blob\",\"Hash\":\"{cid_str}\",\"Size\":\"41\"}}").as_bytes(),
        );
        let (base, rx) = spawn_mock(resp);

        let mut be = LiveBackend::new(cfg_for(&base));
        let cid = be.put_car(sealed).unwrap();

        // CID parsed from the provider response, stored verbatim as locator.
        assert_eq!(cid, Cid(cid_str.as_bytes().to_vec()));

        // Assert the request shape the provider actually received.
        let req = rx.recv().unwrap();
        assert!(req.request_line.starts_with("POST /api/v0/add HTTP/1.1"), "{}", req.request_line);
        assert_eq!(req.header("Authorization"), Some("Bearer test-key-abc123"));
        let ctype = req.header("Content-Type").unwrap();
        assert!(ctype.starts_with("multipart/form-data; boundary="), "{ctype}");
        // The CAR body is the sealed ciphertext, carried verbatim inside the part.
        assert!(
            find_subslice(&req.body, sealed).is_some(),
            "multipart body must carry the sealed bytes verbatim"
        );
        assert!(find_subslice(&req.body, b"name=\"file\"").is_some());
    }

    #[test]
    fn get_fetches_from_gateway_and_returns_bytes() {
        let stored = b"SEALED-ciphertext-bytes-for-retrieval";
        let (base, rx) = spawn_mock(http_response("200 OK", stored));
        let mut be = LiveBackend::new(cfg_for(&base));
        let cid = Cid(b"bafkreitestcidforgetpath".to_vec());
        let got = be.get(&cid).unwrap();
        assert_eq!(got, stored);
        let req = rx.recv().unwrap();
        assert!(
            req.request_line.starts_with("GET /ipfs/bafkreitestcidforgetpath HTTP/1.1"),
            "{}",
            req.request_line
        );
    }

    #[test]
    fn get_404_is_not_found() {
        let (base, _rx) = spawn_mock(http_response("404 Not Found", b"not here"));
        let mut be = LiveBackend::new(cfg_for(&base));
        let err = be.get(&Cid(b"bafkreighost".to_vec())).unwrap_err();
        assert_eq!(err, BackendError::NotFound);
    }

    #[test]
    fn put_car_non_200_is_unavailable() {
        let (base, _rx) = spawn_mock(http_response("401 Unauthorized", b"bad key"));
        let mut be = LiveBackend::new(cfg_for(&base));
        let err = be.put_car(b"x").unwrap_err();
        match err {
            BackendError::Unavailable(m) => assert!(m.contains("401"), "{m}"),
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn deal_status_empty_array_is_acknowledged() {
        let (base, rx) = spawn_mock(http_response("200 OK", b"[]"));
        let mut be = LiveBackend::new(cfg_for(&base));
        let st = be.deal_status(&Cid(b"bafkreitest".to_vec())).unwrap();
        assert_eq!(st, DealStatus::Acknowledged);
        let req = rx.recv().unwrap();
        assert!(
            req.request_line.contains("cid=bafkreitest"),
            "{}",
            req.request_line
        );
    }

    #[test]
    fn deal_status_with_deals_is_deal_active() {
        let body = br#"[{"dealId":12345,"storageProvider":"f01234","expirationEpoch":5000000}]"#;
        let (base, _rx) = spawn_mock(http_response("200 OK", body));
        let mut be = LiveBackend::new(cfg_for(&base));
        let st = be.deal_status(&Cid(b"bafkreitest".to_vec())).unwrap();
        assert_eq!(
            st,
            DealStatus::DealActive(vec![DealInfo {
                deal_id: Some(12345),
                provider: "f01234".to_string(),
                end_epoch: Some(5_000_000),
            }])
        );
    }

    #[test]
    fn deal_status_unreachable_is_unknown() {
        // Nothing listening on this port ⇒ connect fails ⇒ honest Unknown.
        let cfg = LiveConfig {
            api_key: "k".into(),
            upload_url: "http://127.0.0.1:1/api/v0/add".into(),
            gateway_url: "http://127.0.0.1:1/ipfs".into(),
            deal_status_url: "http://127.0.0.1:1/deal_status".into(),
            timeout: Duration::from_millis(500),
        };
        let mut be = LiveBackend::new(cfg);
        assert_eq!(be.deal_status(&Cid(b"x".to_vec())).unwrap(), DealStatus::Unknown);
    }

    #[test]
    fn https_url_is_rejected_with_guidance() {
        let err = Url::parse("https://node.lighthouse.storage/api/v0/add").unwrap_err();
        match err {
            BackendError::Unavailable(m) => {
                assert!(m.contains("TLS"), "{m}");
                assert!(m.contains("LIGHTHOUSE_"), "{m}");
            }
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn from_env_without_key_refuses() {
        // Ensure the key is absent for this process (tests share the env; this
        // test only asserts the no-key branch when it is genuinely unset).
        if std::env::var(ENV_API_KEY).is_err() {
            let err = LiveBackend::from_env().unwrap_err();
            match err {
                BackendError::Unavailable(m) => assert!(m.contains(ENV_API_KEY), "{m}"),
                other => panic!("expected Unavailable, got {other:?}"),
            }
        }
    }

    #[test]
    fn chunked_response_is_decoded() {
        // "Wiki" + "pedia" as two chunks (classic RFC example shape).
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let resp = parse_http_response(raw).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"Wikipedia");
    }

    /// Real Lighthouse smoke test — an operator-gated LIVE round-trip.
    ///
    /// It is `#[ignore]`d so the normal `cargo test --features live` run (which
    /// exercises the mock-server tests above) never touches the network. An
    /// operator opts in explicitly with the documented command:
    ///
    /// ```sh
    /// export LIGHTHOUSE_API_KEY=<free key from lighthouse.storage>
    /// # no TLS is linked in-crate — front the HTTPS hosts with a local proxy:
    /// #   stunnel/socat 127.0.0.1:8443 -> node.lighthouse.storage:443
    /// #   stunnel/socat 127.0.0.1:8444 -> gateway.lighthouse.storage:443
    /// export LIGHTHOUSE_UPLOAD_URL=http://127.0.0.1:8443/api/v0/add
    /// export LIGHTHOUSE_GATEWAY_URL=http://127.0.0.1:8444/ipfs
    /// cargo test --features live real_lighthouse_smoke_if_token_present \
    ///     -- --nocapture --ignored
    /// ```
    ///
    /// Honesty rails: even when selected via `--ignored`, the test is a
    /// documented **no-op** (it returns `Ok`, printing why) if no
    /// `LIGHTHOUSE_API_KEY` is set or the endpoints are still the default HTTPS
    /// hosts that this TLS-less client cannot reach. This crate never fabricates
    /// a token or a CID: the PASS below only happens against a real provider.
    #[test]
    #[ignore = "live Lighthouse round-trip: needs LIGHTHOUSE_API_KEY + a local TLS proxy \
                (LIGHTHOUSE_UPLOAD_URL/LIGHTHOUSE_GATEWAY_URL); run with --ignored"]
    fn real_lighthouse_smoke_if_token_present() {
        let backend = match LiveBackend::from_env() {
            Ok(b) => b,
            Err(_) => {
                eprintln!(
                    "SKIP real_lighthouse_smoke: no {ENV_API_KEY} set — mock tests cover the client. \
                     To go live: set {ENV_API_KEY}, and (since no TLS is linked) point \
                     {ENV_UPLOAD_URL}/{ENV_GATEWAY_URL} at a local https→http TLS proxy."
                );
                return;
            }
        };
        // If the endpoints are still the default HTTPS hosts, we cannot reach
        // them without TLS; report honestly rather than pretend.
        if backend.config().upload_url.starts_with("https://") {
            eprintln!(
                "SKIP real_lighthouse_smoke: key present but {ENV_UPLOAD_URL} is HTTPS and no TLS \
                 is linked in-crate — set {ENV_UPLOAD_URL}/{ENV_GATEWAY_URL} to an http:// TLS proxy."
            );
            return;
        }
        let mut backend = backend;

        // The blob is Postern-SEALED ciphertext-shaped: opaque, non-plaintext
        // bytes, uniquified so re-runs upload distinct content. The seam only
        // ever sees ciphertext — provider confidentiality is never trusted.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut sealed = b"POSTERN-SEALED-smoke-\x00\x01\x02\x03-".to_vec();
        sealed.extend_from_slice(nonce.to_le_bytes().as_slice());

        // 1) Upload the sealed ciphertext; the provider returns a CID LOCATOR.
        let cid = backend.put_car(&sealed).expect("live upload should succeed");
        let cid_str = String::from_utf8_lossy(cid.as_bytes()).to_string();
        assert!(!cid_str.trim().is_empty(), "provider must return a non-empty CID");
        eprintln!("REAL upload OK — provider CID: {cid_str}");

        // 2) Re-fetch by CID and assert byte-for-byte identity. The bytes are
        //    UNTRUSTED at this seam (the caller re-verifies the SHAKE-256 anchor
        //    upstream); here we only prove the transport round-trips faithfully.
        let fetched = backend.get(&cid).expect("live retrieve should succeed");
        assert_eq!(fetched, sealed, "retrieved ciphertext must equal uploaded");
        eprintln!("REAL re-fetch OK — {} bytes, byte-identical", fetched.len());

        // 3) Persistence probe (informational, non-fatal). A just-uploaded blob
        //    is typically HOT-only (no on-chain deal yet), so this is logged,
        //    never asserted — asserting DealActive would be dishonest here.
        match backend.deal_status(&cid) {
            Ok(status) => eprintln!("deal_status probe: {status:?}"),
            Err(e) => eprintln!("deal_status probe errored (non-fatal): {e:?}"),
        }
    }
}
