//! Postern Tor — the in-process Tor layer for Postern Labs products.
//!
//! A thin wrapper over [`arti_client`] (the Tor Project's Rust Tor, Apache-2.0 OR
//! MIT) so a product opens Tor circuits **in-process** — no Orbot, no system
//! `tor` daemon, no SOCKS port to leak on. The wallet RPC, the messenger, and the
//! container all talk to the network through one bootstrapped [`PosternTor`] —
//! but distinct product identities MUST use isolated circuits (see
//! [`PosternTor::for_identity`] / [`PosternTor::connect_isolated`]), or an exit
//! relay / destination can correlate "this wallet" with "this messenger account"
//! by shared-circuit timing and exit IP.
//!
//! SCOPE (honest): by default this crate is an onion-service **client** only
//! (arti's `onion-service-client` feature) — it can *connect to* `.onion`
//! services. **Hosting** an onion service — publishing an ephemeral `.onion`
//! drop, the transport `postern-courier` needs — lives behind the **opt-in
//! `onion-service` feature** ([`onion_host`], arti `onion-service-service`).
//! It is OFF by default so client-only callers stay lean. The hosting path is
//! UNAUDITED reference-prototype: it is exercised only by an ignored live test
//! (real HS publish needs the network and minutes), the onion **signing key is
//! held in arti's configured keystore** (custody is "at-rest on the running
//! host", not a hardware token), and it has **no replay/DoS hardening beyond a
//! payload-size cap** — do not read any Postern doc as claiming otherwise.
//!
//! ```no_run
//! # async fn demo() -> Result<(), postern_tor::TorError> {
//! let tor = postern_tor::PosternTor::bootstrap().await?;
//! // Each product identity gets its own circuit-isolated handle.
//! let wallet_tor = tor.for_identity();
//! // A Tor-anonymised TCP stream to a node's RPC host; layer TLS/HTTP on top.
//! let mut stream = wallet_tor.connect("blochv-node.example", 443).await?;
//! # let _ = &mut stream;
//! # Ok(()) }
//! ```
//!
//! Honesty: bootstrapping a live Tor client needs network + tens of seconds and
//! is NOT exercised in CI here — the crate is verified to **compile**; the live
//! path is covered by an ignored integration test and on-device.

use std::sync::Arc;
use std::time::Duration;

use arti_client::{StreamPrefs, TorClient, TorClientConfig};
use tor_rtcompat::PreferredRuntime;

/// Re-exported so callers can hold one token per identity and pass it to
/// [`PosternTor::connect_isolated`]: streams sharing a token may share
/// circuits with each other, never with other tokens.
pub use arti_client::IsolationToken;

/// Hard cap on a JSON-RPC response body+headers read over Tor. A hostile node
/// or onion service must not be able to stream gigabytes into the wallet's
/// memory; hitting the cap is an ERROR, never a silent truncation.
pub const MAX_RPC_RESPONSE: usize = 2 * 1024 * 1024; // 2 MiB

/// Wall-clock budget for one whole JSON-RPC exchange (connect + write + read).
/// Without it a peer that never sends `\r\n\r\n` and never closes — stream end
/// is entirely the server's choice under `Connection: close` — hangs the
/// calling task forever.
pub const RPC_TIMEOUT: Duration = Duration::from_secs(60);

/// Errors from the Postern Tor layer.
#[derive(Debug, thiserror::Error)]
pub enum TorError {
    #[error("tor bootstrap failed: {0}")]
    Bootstrap(String),
    #[error("tor connect failed: {0}")]
    Connect(String),
    #[error("rpc over tor failed: {0}")]
    Rpc(String),
    /// Onion-service HOSTING errors (only produced with the `onion-service`
    /// feature). Kept in the shared enum so callers match one error type.
    #[error("onion service hosting failed: {0}")]
    Onion(String),
}

/// Reject `host`/`path` values that could split or inject into the hand-rolled
/// HTTP/1.1 request head (CRLF injection): control bytes and whitespace are
/// never legal in either position.
fn validate_request_token(kind: &str, value: &str) -> Result<(), TorError> {
    if value.is_empty()
        || value.bytes().any(|b| b.is_ascii_control() || b == b' ' || b == 0)
    {
        return Err(TorError::Rpc(format!("invalid {kind} for HTTP request")));
    }
    Ok(())
}

/// Build the raw HTTP/1.1 POST for a JSON-RPC call. Pure + offline-testable.
/// `Connection: close` so the exit reads to EOF — the node's RPC sets a
/// Content-Length, so the whole body arrives before the stream closes.
/// `host`/`path` must already be validated (see [`validate_request_token`]).
fn build_rpc_request(host: &str, path: &str, body: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n\
         {body}",
        path = path,
        host = host,
        len = body.len(),
        body = body,
    )
}

/// A bootstrapped, in-process Tor client shared across a product's connections.
/// Cheap to clone — circuits are pooled internally by Arti. Clones share
/// circuit isolation; call [`PosternTor::for_identity`] to get a handle whose
/// streams never share circuits with any other handle.
#[derive(Clone)]
pub struct PosternTor {
    // Arc because arti ≥ 0.43 hands out `Arc<TorClient>` (TorClient itself is
    // no longer `Clone`); the handle semantics here are unchanged.
    client: Arc<TorClient<PreferredRuntime>>,
}

impl PosternTor {
    /// Bootstrap an in-process Tor client with the default (anonymous) config.
    /// Blocks until the client has a usable view of the network — seconds on a
    /// good link. Call once per process and clone the handle.
    pub async fn bootstrap() -> Result<Self, TorError> {
        let config = TorClientConfig::default();
        let client = TorClient::create_bootstrapped(config)
            .await
            .map_err(|e| TorError::Bootstrap(e.to_string()))?;
        Ok(Self { client })
    }

    /// Wrap an already-built Arti client (e.g. one configured with a custom
    /// state/cache dir or bridges) into the Postern handle. (Arti hands out
    /// `Arc<TorClient>` since 0.43; pass it straight through.)
    pub fn from_client(client: Arc<TorClient<PreferredRuntime>>) -> Self {
        Self { client }
    }

    /// A handle whose streams are **circuit-isolated** from every other handle
    /// (including the parent): same bootstrapped Tor, disjoint circuits.
    ///
    /// SECURITY: distinct product identities (wallet vs. messenger account vs.
    /// container) MUST each use their own `for_identity()` handle. Otherwise
    /// Arti may put their streams on the same circuit, and the shared exit +
    /// correlated timing lets an observer link the identities.
    pub fn for_identity(&self) -> Self {
        Self { client: self.client.isolated_client() }
    }

    /// Open a Tor-anonymised TCP stream to `host:port`. `host` is resolved by the
    /// exit relay (never locally — no DNS leak). Layer TLS + HTTP on the returned
    /// stream (it implements `AsyncRead`/`AsyncWrite`).
    ///
    /// Streams from the same handle may share circuits. For cross-identity
    /// separation use [`PosternTor::for_identity`] or
    /// [`PosternTor::connect_isolated`].
    pub async fn connect(
        &self,
        host: &str,
        port: u16,
    ) -> Result<arti_client::DataStream, TorError> {
        self.client
            .connect((host, port))
            .await
            .map_err(|e| TorError::Connect(e.to_string()))
    }

    /// Like [`PosternTor::connect`], but the stream joins the circuit-isolation
    /// group of `token`: streams with equal tokens may share circuits with each
    /// other and with nothing else. Hold one [`IsolationToken`] per identity
    /// (`IsolationToken::new()`) and pass it for every stream of that identity.
    pub async fn connect_isolated(
        &self,
        host: &str,
        port: u16,
        token: IsolationToken,
    ) -> Result<arti_client::DataStream, TorError> {
        let mut prefs = StreamPrefs::new();
        prefs.set_isolation(token);
        self.client
            .connect_with_prefs((host, port), &prefs)
            .await
            .map_err(|e| TorError::Connect(e.to_string()))
    }

    /// The underlying Arti client, for advanced use (onion-service client
    /// streams, custom `StreamPrefs`, per-identity sub-clients).
    pub fn client(&self) -> &TorClient<PreferredRuntime> {
        &self.client
    }

    /// Make a JSON-RPC call to a node over Tor. Designed for a node exposed as
    /// an **onion service** (`host` = `<addr>.onion`, no TLS needed — Tor gives
    /// end-to-end encryption to the service). Opens a fresh Tor stream, POSTs
    /// `{jsonrpc,id,method,params}` to `path`, and returns the parsed JSON-RPC
    /// **envelope** (the whole `{jsonrpc,id,result|error}` object — the caller
    /// checks `result`/`error`). The node never learns the client's IP, and the
    /// host is resolved at the exit/onion, not locally.
    ///
    /// SECURITY — non-`.onion` hosts: this is plain HTTP, so for a clearnet
    /// host the **exit relay is an active man-in-the-middle** — it can read and
    /// **rewrite** the RPC in both directions (lie about chain state, swap
    /// addresses in responses, censor). Anonymity is preserved; integrity is
    /// NOT. Use `.onion` nodes; treat any clearnet-HTTP response as untrusted
    /// input. (An `https://` clearnet node would need a TLS layer on the
    /// stream; the privacy-native path is the onion node.)
    ///
    /// Hardening: the whole exchange is bounded by [`RPC_TIMEOUT`] and the
    /// response read is capped at [`MAX_RPC_RESPONSE`] (error, not truncation)
    /// so a hostile peer can neither hang the caller nor exhaust memory. The
    /// response must be a non-chunked `HTTP/1.x 200`.
    ///
    /// Streams from the same handle may share circuits — per-identity callers
    /// should invoke this on a [`PosternTor::for_identity`] handle.
    pub async fn json_rpc(
        &self,
        host: &str,
        port: u16,
        path: &str,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, TorError> {
        validate_request_token("host", host)?;
        validate_request_token("path", path)?;

        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params
        })
        .to_string();
        let req = build_rpc_request(host, path, &body);

        tokio::time::timeout(RPC_TIMEOUT, self.json_rpc_exchange(host, port, &req))
            .await
            .map_err(|_| TorError::Rpc(format!("rpc timed out after {RPC_TIMEOUT:?}")))?
    }

    /// The unbounded inner exchange — always called under [`RPC_TIMEOUT`].
    async fn json_rpc_exchange(
        &self,
        host: &str,
        port: u16,
        req: &str,
    ) -> Result<serde_json::Value, TorError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = self.connect(host, port).await?;
        stream.write_all(req.as_bytes()).await.map_err(|e| TorError::Rpc(e.to_string()))?;
        stream.flush().await.map_err(|e| TorError::Rpc(e.to_string()))?;

        // Capped read: take one byte more than the cap so an at-limit response
        // is distinguishable from an over-limit one — over-limit is an ERROR.
        let mut raw = Vec::new();
        let mut limited = stream.take(MAX_RPC_RESPONSE as u64 + 1);
        limited.read_to_end(&mut raw).await.map_err(|e| TorError::Rpc(e.to_string()))?;
        if raw.len() > MAX_RPC_RESPONSE {
            return Err(TorError::Rpc(format!(
                "response exceeds {MAX_RPC_RESPONSE}-byte cap"
            )));
        }

        parse_rpc_response(&raw)
    }
}

/// Parse a raw HTTP/1.x response into the JSON-RPC envelope. Pure +
/// offline-testable. Requires a 200 status, refuses `Transfer-Encoding:
/// chunked` (chunk framing would corrupt the naive body split), and surfaces
/// non-200 statuses as errors instead of confusing JSON parse failures.
fn parse_rpc_response(raw: &[u8]) -> Result<serde_json::Value, TorError> {
    let text = String::from_utf8_lossy(raw);
    let split = text.find("\r\n\r\n").ok_or_else(|| TorError::Rpc("no HTTP body".into()))?;
    let head = &text[..split];
    let status_line = head.lines().next().unwrap_or("");
    let mut status_parts = status_line.split(' ');
    let version = status_parts.next().unwrap_or("");
    let code = status_parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") || code != "200" {
        return Err(TorError::Rpc(format!("http status not 200: {status_line:?}")));
    }
    if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        return Err(TorError::Rpc("chunked transfer encoding not supported".into()));
    }
    let body = text[split + 4..].trim();
    serde_json::from_str(body).map_err(|e| TorError::Rpc(format!("parse response: {e}")))
}

/// Onion-service **hosting** — the additive `onion-service`-feature path.
///
/// This is what turns `postern-courier`'s planned "ephemeral Tor onion drop"
/// into a real transport: [`OnionDrop::publish`] launches an in-process arti
/// onion service, prints back its `.onion` address, and [`OnionDrop::accept`]
/// hands the caller the next inbound `DataStream` to speak an app protocol on.
///
/// HONEST LIMITS (reference-prototype, UNAUDITED):
/// - **Reachability latency**: after `publish` returns, the descriptor still
///   has to reach the HSDirs — a fresh service is typically reachable only
///   after tens of seconds to a couple of minutes. `accept` simply waits;
///   callers that need a readiness signal use [`OnionDrop::wait_reachable`]
///   (built on arti's status events, see [`DropStatus`]). "Reachable" there
///   means **arti believes** the descriptor is published and the service
///   reachable — it is NOT an anonymity, availability, or DoS-resistance
///   claim, and a client may still fail to connect.
/// - **Key custody**: the onion service's identity key lives in the arti
///   client's configured keystore (on-disk state dir under the default config).
///   "Ephemeral" here means the *drop* is short-lived and torn down when
///   `OnionDrop` drops — not that the key never touches disk.
/// - **No app-layer auth / anti-replay here**: this layer only moves bytes.
///   Confidentiality + recipient-binding are the caller's job (courier's hybrid
///   seal); onion-service client authorization is not configured.
#[cfg(feature = "onion-service")]
pub mod onion_host {
    use super::{PosternTor, TorError};
    use futures::{Stream, StreamExt};
    use safelog::DisplayRedacted;
    use std::pin::Pin;
    use std::time::Duration;
    use tor_cell::relaycell::msg::Connected;
    use tor_hsservice::{
        config::OnionServiceConfigBuilder, handle_rend_requests, status::State, HsNickname,
        RunningOnionService, StreamRequest,
    };
    use tor_proto::stream::IncomingStreamRequest;

    /// Coarse readiness of a published drop, mapped from arti's
    /// [`tor_hsservice::status::State`] (see [`map_state`]).
    ///
    /// HONESTY: [`DropStatus::Reachable`] means **arti reports** the descriptor
    /// published and the service believes it is reachable. It is a liveness
    /// hint, NOT an anonymity, availability, or DoS-resistance claim — a
    /// client can still fail to reach the service, and nothing here hardens
    /// the drop beyond what the module docs already (don't) promise.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
    pub enum DropStatus {
        /// Building introduction points / publishing the first descriptor.
        Bootstrapping,
        /// Arti believes the service is reachable (arti `Running` or
        /// `DegradedReachable` — degraded-but-reachable counts as reachable).
        Reachable,
        /// Running but unlikely to be reachable (arti `DegradedUnreachable`,
        /// e.g. descriptor upload to some HSDirs failed). Also the
        /// conservative bucket for any future arti state this crate does not
        /// know (`State` is `#[non_exhaustive]`): unknown ⇒ NOT reachable.
        Degraded,
        /// Recovering from a minor interruption (dead intro point, transient
        /// upload failure); unlikely to be reachable right now.
        Recovering,
        /// The service failed and could not recover. Terminal for waiting.
        Broken,
        /// The service is not launched / has been shut down. Terminal.
        Shutdown,
    }

    impl DropStatus {
        /// Whether arti believes the service is reachable (see the type-level
        /// honesty note — a hint, not a guarantee).
        pub fn is_reachable(self) -> bool {
            matches!(self, Self::Reachable)
        }

        /// Terminal-for-waiting states: no amount of waiting turns these into
        /// [`DropStatus::Reachable`] on their own.
        pub fn is_terminal(self) -> bool {
            matches!(self, Self::Broken | Self::Shutdown)
        }
    }

    /// Pure mapping from arti's onion-service [`State`] to [`DropStatus`].
    /// `Running` AND `DegradedReachable` map to [`DropStatus::Reachable`]
    /// (mirroring arti's own `State::is_fully_reachable`). `State` is
    /// `#[non_exhaustive]`, so an unknown future variant maps conservatively
    /// to [`DropStatus::Degraded`] — never spuriously "reachable" or
    /// spuriously terminal.
    fn map_state(state: State) -> DropStatus {
        match state {
            State::Bootstrapping => DropStatus::Bootstrapping,
            State::Running | State::DegradedReachable => DropStatus::Reachable,
            State::DegradedUnreachable => DropStatus::Degraded,
            State::Recovering => DropStatus::Recovering,
            State::Broken => DropStatus::Broken,
            State::Shutdown => DropStatus::Shutdown,
            _ => DropStatus::Degraded,
        }
    }

    /// Wait on `events` until the first [`DropStatus::Reachable`], failing
    /// FAST on a terminal status ([`DropStatus::Broken`] /
    /// [`DropStatus::Shutdown`] — no waiting out the deadline), on the stream
    /// ending, or on `deadline` expiring. Generic over the stream so the wait
    /// logic is testable offline with mock streams (see the tests).
    ///
    /// This is the engine behind [`OnionDrop::wait_reachable`].
    pub async fn wait_reachable_on(
        mut events: impl Stream<Item = DropStatus> + Unpin,
        deadline: Duration,
    ) -> Result<(), TorError> {
        let wait = async {
            while let Some(status) = events.next().await {
                if status.is_reachable() {
                    return Ok(());
                }
                if status.is_terminal() {
                    return Err(TorError::Onion(format!(
                        "onion service entered terminal state {status:?} before becoming reachable"
                    )));
                }
            }
            Err(TorError::Onion(
                "status stream ended before the onion service became reachable".into(),
            ))
        };
        tokio::time::timeout(deadline, wait).await.map_err(|_| {
            TorError::Onion(format!("onion service not reachable within {deadline:?}"))
        })?
    }

    /// A live, published ephemeral onion service. While this value is alive the
    /// service stays up; dropping it tears the service down (the arti
    /// background tasks stop and the descriptor expires).
    pub struct OnionDrop {
        /// Kept alive so the service keeps running; also the source of the
        /// `.onion` address.
        service: std::sync::Arc<RunningOnionService>,
        /// The `<b32>.onion` address to hand to the peer out-of-band.
        onion_address: String,
        /// Incoming BEGIN streams, already flattened from rendezvous requests.
        requests: Pin<Box<dyn Stream<Item = StreamRequest> + Send>>,
    }

    /// Validate `nickname` against arti's `HsNickname` rules (`[a-z0-9_]`)
    /// without touching the network. Pulled out of [`OnionDrop::publish`] so
    /// it can be exercised offline.
    fn parse_nickname(nickname: &str) -> Result<HsNickname, TorError> {
        nickname
            .parse()
            .map_err(|e| TorError::Onion(format!("bad nickname {nickname:?}: {e}")))
    }

    impl OnionDrop {
        /// Launch and publish an ephemeral onion service on `tor`'s in-process
        /// arti client. `nickname` names the service's keys/state within arti
        /// (`[a-z0-9_]`, see arti's `HsNickname` rules); use a fresh nickname
        /// per drop for a fresh address.
        ///
        /// Returns once the service is *launched* (not yet necessarily
        /// reachable — see the module note on descriptor-publish latency).
        pub async fn publish(tor: &PosternTor, nickname: &str) -> Result<Self, TorError> {
            let nick: HsNickname = parse_nickname(nickname)?;
            let cfg = OnionServiceConfigBuilder::default()
                .nickname(nick)
                .build()
                .map_err(|e| TorError::Onion(format!("onion config: {e}")))?;

            let (service, rend_requests) = tor
                .client()
                .launch_onion_service(cfg)
                .map_err(|e| TorError::Onion(format!("launch: {e}")))?
                .ok_or_else(|| TorError::Onion("onion service disabled in config".into()))?;

            // `HsId` redacts its `.onion` in Display by default (log hygiene);
            // we WANT the full address to hand to the peer, so render it
            // explicitly via the DisplayRedacted trait's unredacted form.
            let onion_address = service
                .onion_address()
                .ok_or_else(|| TorError::Onion("no onion address for launched service".into()))?
                .display_unredacted()
                .to_string();

            let requests = Box::pin(handle_rend_requests(rend_requests));

            Ok(Self { service, onion_address, requests })
        }

        /// The `<b32>.onion` address to hand the peer (over the same
        /// out-of-band channel used to exchange the courier key fingerprint).
        pub fn onion_address(&self) -> &str {
            &self.onion_address
        }

        /// Reference to the running service (advanced use / to keep alive).
        pub fn service(&self) -> &RunningOnionService {
            &self.service
        }

        /// The current readiness of this drop, mapped from arti's status.
        /// See [`DropStatus`] for what "reachable" does — and does NOT — mean.
        pub fn status(&self) -> DropStatus {
            map_state(self.service.status().state())
        }

        /// A stream of [`DropStatus`] updates over arti's status events. The
        /// underlying watch stream yields the *current* status first, then
        /// changes (coalescing intermediate updates under backpressure).
        pub fn status_events(&self) -> impl Stream<Item = DropStatus> {
            self.service.status_events().map(|s| map_state(s.state()))
        }

        /// Wait (up to `deadline`) until arti believes this drop is reachable
        /// — i.e. the descriptor reached the HSDirs and the service reports
        /// [`DropStatus::Reachable`]. Fails fast (without waiting out the
        /// deadline) if the service goes [`DropStatus::Broken`] or
        /// [`DropStatus::Shutdown`], and with [`TorError::Onion`] on deadline
        /// expiry. Thin wrapper over [`wait_reachable_on`].
        ///
        /// HONESTY: success is arti's self-report of reachability, not a
        /// proof a client can connect, and not an anonymity/availability/DoS
        /// claim (this hosting path stays an UNAUDITED reference-prototype).
        pub async fn wait_reachable(&self, deadline: Duration) -> Result<(), TorError> {
            wait_reachable_on(Box::pin(self.status_events()), deadline).await
        }

        /// Wait for and accept the next inbound BEGIN stream, returning a
        /// `DataStream` (`AsyncRead`/`AsyncWrite`) to speak an app protocol on.
        /// Non-BEGIN requests (e.g. BEGIN_DIR) are rejected and skipped — this
        /// is a data drop, not a directory. Returns an error if the request
        /// stream ends (service torn down) before a BEGIN arrives.
        pub async fn accept(&mut self) -> Result<arti_client::DataStream, TorError> {
            while let Some(req) = self.requests.next().await {
                match req.request() {
                    IncomingStreamRequest::Begin(_) => {
                        return req
                            .accept(Connected::new_empty())
                            .await
                            .map_err(|e| TorError::Onion(format!("accept stream: {e}")));
                    }
                    // Anything else on a data drop is anomalous; drop its
                    // circuit and keep waiting for a real BEGIN.
                    _ => {
                        let _ = req.shutdown_circuit();
                        continue;
                    }
                }
            }
            Err(TorError::Onion("request stream ended before a BEGIN".into()))
        }
    }

    /// Offline: nickname validation, the State→DropStatus mapping table, and
    /// the wait logic over mock streams — no network, no bootstrap. The one
    /// live test (real publish + wait) is `#[ignore]`d.
    #[cfg(all(test, feature = "onion-service"))]
    mod tests {
        use super::{map_state, parse_nickname, wait_reachable_on, DropStatus, State};
        use crate::TorError;
        use futures::stream;
        use std::time::Duration;

        #[test]
        fn valid_nickname_parses() {
            assert!(parse_nickname("postern_courier_drop").is_ok());
        }

        #[test]
        fn invalid_nicknames_are_rejected() {
            // Slugs allow `-` mid-name but never as the first character.
            for bad in ["Bad Name", "UPPER", "", "-leading-dash"] {
                match parse_nickname(bad) {
                    Err(TorError::Onion(_)) => {}
                    other => panic!("expected TorError::Onion for {bad:?}, got {other:?}"),
                }
            }
        }

        /// The full mapping table: every arti 0.44 `State` variant lands where
        /// the plan says, and Running + DegradedReachable BOTH count reachable.
        #[test]
        fn state_mapping_table() {
            let table = [
                (State::Shutdown, DropStatus::Shutdown),
                (State::Bootstrapping, DropStatus::Bootstrapping),
                (State::DegradedReachable, DropStatus::Reachable),
                (State::DegradedUnreachable, DropStatus::Degraded),
                (State::Running, DropStatus::Reachable),
                (State::Recovering, DropStatus::Recovering),
                (State::Broken, DropStatus::Broken),
            ];
            for (arti, expected) in table {
                assert_eq!(map_state(arti), expected, "map_state({arti:?})");
            }
        }

        /// Reachable/terminal predicates agree with the wait semantics, and
        /// our "reachable" mirrors arti's own is_fully_reachable.
        #[test]
        fn drop_status_predicates() {
            assert!(DropStatus::Reachable.is_reachable());
            for s in [
                DropStatus::Bootstrapping,
                DropStatus::Degraded,
                DropStatus::Recovering,
                DropStatus::Broken,
                DropStatus::Shutdown,
            ] {
                assert!(!s.is_reachable(), "{s:?} must not be reachable");
            }
            assert!(DropStatus::Broken.is_terminal());
            assert!(DropStatus::Shutdown.is_terminal());
            assert!(!DropStatus::Reachable.is_terminal());
            assert!(!DropStatus::Bootstrapping.is_terminal());
            for s in [
                State::Shutdown,
                State::Bootstrapping,
                State::DegradedReachable,
                State::DegradedUnreachable,
                State::Running,
                State::Recovering,
                State::Broken,
            ] {
                assert_eq!(
                    map_state(s).is_reachable(),
                    s.is_fully_reachable(),
                    "reachability disagreement on {s:?}"
                );
            }
        }

        #[tokio::test]
        async fn wait_resolves_on_immediate_reachable() {
            let events = stream::iter([DropStatus::Reachable]);
            wait_reachable_on(events, Duration::from_secs(5)).await.expect("reachable => Ok");
        }

        #[tokio::test]
        async fn wait_resolves_after_bootstrapping() {
            let events = stream::iter([
                DropStatus::Bootstrapping,
                DropStatus::Degraded,
                DropStatus::Recovering,
                DropStatus::Reachable,
            ]);
            wait_reachable_on(events, Duration::from_secs(5)).await.expect("eventually Ok");
        }

        /// Broken fails FAST: the deadline is an hour, but the test finishes
        /// immediately because terminal states short-circuit the wait.
        #[tokio::test]
        async fn wait_fails_fast_on_broken() {
            let events = stream::iter([DropStatus::Bootstrapping, DropStatus::Broken]);
            let err = wait_reachable_on(events, Duration::from_secs(3600))
                .await
                .expect_err("Broken => Err");
            match err {
                TorError::Onion(msg) => {
                    assert!(msg.contains("Broken"), "unexpected message: {msg}")
                }
                other => panic!("expected TorError::Onion, got {other:?}"),
            }
        }

        /// Shutdown is terminal too (a torn-down service never becomes
        /// reachable by waiting).
        #[tokio::test]
        async fn wait_fails_fast_on_shutdown() {
            let events = stream::iter([DropStatus::Shutdown]);
            let err = wait_reachable_on(events, Duration::from_secs(3600))
                .await
                .expect_err("Shutdown => Err");
            assert!(err.to_string().contains("Shutdown"), "unexpected: {err}");
        }

        /// A stream that ends without ever reporting reachable is an error,
        /// not a hang or a silent Ok.
        #[tokio::test]
        async fn wait_fails_when_stream_ends_unreachable() {
            let events = stream::iter([DropStatus::Bootstrapping, DropStatus::Recovering]);
            let err = wait_reachable_on(events, Duration::from_secs(5))
                .await
                .expect_err("ended stream => Err");
            assert!(err.to_string().contains("ended"), "unexpected: {err}");
        }

        /// Deadline expiry under tokio's PAUSED clock: a never-yielding stream
        /// with a 120s deadline errs "immediately" in wall-clock terms (the
        /// paused clock auto-advances), proving the timeout path without
        /// real waiting.
        #[tokio::test(start_paused = true)]
        async fn wait_fails_on_deadline_without_wall_clock_waiting() {
            let events = stream::pending::<DropStatus>();
            let err = wait_reachable_on(events, Duration::from_secs(120))
                .await
                .expect_err("deadline => Err");
            match err {
                TorError::Onion(msg) => {
                    assert!(msg.contains("not reachable within"), "unexpected message: {msg}")
                }
                other => panic!("expected TorError::Onion, got {other:?}"),
            }
        }

        /// LIVE: real Tor bootstrap + real onion-service publish + waiting for
        /// actual HSDir reachability — network + minutes, NEVER in CI. Run:
        /// `cargo test -p postern-tor --features onion-service -- --ignored`.
        #[tokio::test]
        #[ignore]
        async fn live_publish_and_wait_reachable() {
            let tor = crate::PosternTor::bootstrap().await.expect("bootstrap");
            let drop = super::OnionDrop::publish(&tor, "postern_wait_reachable_test")
                .await
                .expect("publish");
            // Fresh descriptors typically land within a couple of minutes;
            // 5 min is a generous live-test budget, not a product guarantee.
            drop.wait_reachable(Duration::from_secs(300)).await.expect("reachable");
            assert!(drop.status().is_reachable());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Offline: the default config builds without touching the network. Proves
    /// the Arti config surface is wired correctly (the live bootstrap is the
    /// ignored test below).
    #[test]
    fn default_config_builds() {
        let _cfg = TorClientConfig::default();
    }

    #[test]
    fn rpc_request_is_well_formed() {
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}"#;
        let req = build_rpc_request("abc.onion", "/", body);
        assert!(req.starts_with("POST / HTTP/1.1\r\n"));
        assert!(req.contains("Host: abc.onion\r\n"));
        assert!(req.contains("Content-Type: application/json\r\n"));
        assert!(req.contains(&format!("Content-Length: {}\r\n", body.len())));
        assert!(req.contains("Connection: close\r\n"));
        // Body follows the blank line, intact.
        assert!(req.ends_with(&format!("\r\n\r\n{}", body)));
    }

    #[test]
    fn crlf_injection_is_rejected() {
        assert!(validate_request_token("host", "abc.onion").is_ok());
        assert!(validate_request_token("path", "/rpc").is_ok());
        for bad in ["x.onion\r\nX-Evil: 1", "a b", "a\nb", "a\rb", "\0", ""] {
            assert!(validate_request_token("host", bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn rpc_response_parsing() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 26\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1}";
        let v = parse_rpc_response(ok).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");

        // Non-200 statuses surface as status errors, not JSON parse noise.
        let err = parse_rpc_response(b"HTTP/1.1 502 Bad Gateway\r\n\r\n{}").unwrap_err();
        assert!(err.to_string().contains("502"));
        // Chunked framing is refused rather than mis-parsed.
        let chunked =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n0\r\n\r\n";
        assert!(parse_rpc_response(chunked).is_err());
        // Headerless garbage is refused.
        assert!(parse_rpc_response(b"not http at all").is_err());
    }

    /// Live Tor bootstrap + a real circuit — needs network + time, so ignored in
    /// CI. Run explicitly: `cargo test -p postern-tor -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn live_bootstrap_and_connect() {
        let tor = PosternTor::bootstrap().await.expect("bootstrap");
        let _s = tor.connect("check.torproject.org", 443).await.expect("connect");
    }
}
