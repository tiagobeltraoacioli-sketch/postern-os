// SPDX-License-Identifier: MIT OR Apache-2.0
//! A **real** [`Discovery`] over link-local mDNS / DNS-SD.
//!
//! This implements [`postern_pairing::transport::Discovery`] against a live
//! subnet: it advertises a `_postern-pair._tcp.local` service and browses for
//! peers advertising the same, returning a `host:port` dial hint as a
//! [`PeerHint`]. The hand-rolled wire codec lives in [`crate::dns`].
//!
//! ## Rails, restated at the network edge
//!
//! - **LAN-ONLY.** All traffic is to the reserved link-local multicast group
//!   `224.0.0.251:5353` (RFC 6762). Nothing routes off the subnet. No cloud, no
//!   relay, no unicast to an internet host, no telemetry.
//! - **Metadata leak, by construction, opt-in.** Advertising tells the whole
//!   subnet "a Postern pairing endpoint is here". That is inherent to mDNS and
//!   is exactly why [`postern_pairing::transport::NullDiscovery`] is the shipped
//!   default. Turn this on deliberately.
//! - **Minimal advertisement (§2.3).** The TXT carries only a protocol version
//!   and the caller's opaque, rotating `instance_tag`. **No wallet address, no
//!   identity key, no account.** The instance tag disambiguates two boxes on a
//!   subnet; it authenticates nothing.
//! - **Discovery is not authentication.** A discovered peer is an *untrusted*
//!   dial hint. An evil twin can advertise too. The QR-pin + SAS ceremony in
//!   `postern-pairing` is the only thing that authenticates the peer — this
//!   layer just finds a socket to point it at.
//!
//! ## Sandbox honesty
//!
//! Multicast send/receive and binding UDP `:5353` require a real network
//! interface and, on some hosts, coexistence with the OS mDNS responder (handled
//! via `SO_REUSEADDR`/`SO_REUSEPORT`). In a sandbox with no multicast route
//! these operations degrade gracefully (join failures are non-fatal; `browse`
//! simply returns an empty snapshot) rather than erroring. The wire codec and
//! the packet-shaping logic are exercised by deterministic unit tests in
//! [`crate::dns`]; the live path is covered by an `#[ignore]`d integration test
//! you run on a real LAN.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use postern_pairing::transport::{Discovery, PeerHint, TransportError};

use crate::dns;

/// The link-local mDNS multicast group and port (RFC 6762).
const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

/// The DNS-SD service type we advertise and browse.
const SERVICE: &[&str] = &["_postern-pair", "_tcp", "local"];

/// Default browse listen window. mDNS answers trickle in; a few hundred ms is
/// the usual sweet spot for a one-shot browse.
const DEFAULT_BROWSE_WINDOW: Duration = Duration::from_millis(750);

/// TTL for our announcements (seconds). Standard DNS-SD default is 120.
const ADVERT_TTL: u32 = 120;

fn backend<E: std::fmt::Display>(e: E) -> TransportError {
    TransportError::Backend(e.to_string())
}

fn mdns_dest() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(MDNS_GROUP, MDNS_PORT))
}

/// Build a UDP socket bound to `:5353`, sharable with the OS responder via
/// `SO_REUSEADDR`/`SO_REUSEPORT`, and joined to the mDNS group. Used by the
/// responder (which must receive queries sent to the group).
fn bind_mdns_listener(read_timeout: Duration) -> io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    let bind_addr: SocketAddr =
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT));
    sock.bind(&SockAddr::from(bind_addr))?;
    // Membership is best-effort: on a sandbox with no multicast route this can
    // fail; that must not abort advertising, so the caller ignores the error.
    let _ = sock.join_multicast_v4(&MDNS_GROUP, &Ipv4Addr::UNSPECIFIED);
    let _ = sock.set_multicast_loop_v4(true);
    sock.set_read_timeout(Some(read_timeout))?;
    Ok(sock.into())
}

/// Build an ephemeral-port UDP socket for a one-shot browse: it does NOT need
/// `:5353` (we set the QU bit so responders may unicast back to us), but it does
/// join the group so multicast responses are also received.
fn bind_browse_socket(read_timeout: Duration) -> io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    let _ = sock.set_reuse_port(true);
    let bind_addr: SocketAddr =
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    sock.bind(&SockAddr::from(bind_addr))?;
    let _ = sock.join_multicast_v4(&MDNS_GROUP, &Ipv4Addr::UNSPECIFIED);
    let _ = sock.set_multicast_loop_v4(true);
    sock.set_read_timeout(Some(read_timeout))?;
    Ok(sock.into())
}

/// Parse a `PeerHint.lan_hint` like `"192.168.1.20:47001"` into an IPv4 socket
/// address. LAN-only: a non-IPv4 or off-form hint is rejected here.
fn parse_v4_hint(hint: &str) -> Result<SocketAddrV4, TransportError> {
    hint.parse::<SocketAddrV4>()
        .map_err(|_| backend(format!("lan_hint '{hint}' is not an IPv4 host:port")))
}

/// State captured when advertising is live, so `stop` can send a goodbye.
struct AdvertState {
    instance_tag: String,
    addr: SocketAddrV4,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

/// A live mDNS/DNS-SD [`Discovery`]. Off until you call [`advertise`]; browsing
/// is a one-shot each call.
///
/// [`advertise`]: Discovery::advertise
pub struct MdnsDiscovery {
    browse_window: Duration,
    advert: Mutex<Option<AdvertState>>,
}

impl Default for MdnsDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

impl MdnsDiscovery {
    /// A discovery handle with the default browse window.
    pub fn new() -> Self {
        MdnsDiscovery { browse_window: DEFAULT_BROWSE_WINDOW, advert: Mutex::new(None) }
    }

    /// Override how long [`browse`](Discovery::browse) listens for answers.
    pub fn with_browse_window(mut self, window: Duration) -> Self {
        self.browse_window = window;
        self
    }

    /// A stable-ish local hostname label for the SRV/A target. We keep it
    /// generic ("postern-pair") — the real dial address is the A/SRV IP:port, so
    /// the hostname is cosmetic and deliberately non-identifying.
    fn host_label() -> &'static str {
        "postern-pair"
    }

    /// Assemble the announcement/response bytes for our current advertisement.
    fn build_response(instance_tag: &str, addr: &SocketAddrV4, ttl: u32) -> Vec<u8> {
        let instance = vec![instance_tag, SERVICE[0], SERVICE[1], SERVICE[2]];
        let host = vec![Self::host_label(), "local"];
        let txt = vec![
            format!("v={}", postern_pairing::PROTOCOL_VERSION).into_bytes(),
            format!("tag={instance_tag}").into_bytes(),
        ];
        let ad = dns::Advertisement {
            instance,
            service: SERVICE.to_vec(),
            host,
            addr: *addr.ip(),
            port: addr.port(),
            txt,
            ttl,
        };
        dns::encode_advertisement(&ad)
    }
}

impl Discovery for MdnsDiscovery {
    fn advertise(&mut self, hint: &PeerHint) -> Result<(), TransportError> {
        let addr = parse_v4_hint(&hint.lan_hint)?;
        let instance_tag = sanitize_tag(&hint.instance_tag);

        // If we were already advertising, replace cleanly.
        self.stop()?;

        let stop = Arc::new(AtomicBool::new(false));
        // The responder socket must live on :5353 to hear queries. If we cannot
        // bind it (e.g. no multicast in a sandbox), we still keep the advert
        // registered so `stop`/`browse` behave, but we do not spawn a thread.
        let responder = bind_mdns_listener(Duration::from_millis(250));

        let handle = match responder {
            Ok(sock) => {
                let stop_flag = stop.clone();
                let tag = instance_tag.clone();
                let bind_addr = addr;
                Some(std::thread::spawn(move || {
                    responder_loop(sock, tag, bind_addr, stop_flag);
                }))
            }
            Err(_) => None, // degrade gracefully; advertising is best-effort.
        };

        *self.advert.lock().map_err(|_| backend("advert lock poisoned"))? =
            Some(AdvertState { instance_tag, addr, stop, handle });
        Ok(())
    }

    fn browse(&mut self) -> Result<Vec<PeerHint>, TransportError> {
        // One-shot browse: send a PTR query, listen for the window, parse peers.
        let sock = match bind_browse_socket(Duration::from_millis(200)) {
            Ok(s) => s,
            // No multicast route (sandbox): honestly report "found nothing"
            // rather than erroring — matches NullDiscovery's contract shape.
            Err(_) => return Ok(Vec::new()),
        };

        let query = dns::encode_ptr_query(SERVICE);
        // A send failure here is also non-fatal: return an empty snapshot.
        if sock.send_to(&query, mdns_dest()).is_err() {
            return Ok(Vec::new());
        }

        let mut peers: Vec<PeerHint> = Vec::new();
        let deadline = Instant::now() + self.browse_window;
        let mut buf = [0u8; 4096];
        loop {
            if Instant::now() >= deadline {
                break;
            }
            match sock.recv_from(&mut buf) {
                Ok((n, _from)) => {
                    if let Some(msg) = dns::parse(&buf[..n]) {
                        collect_peers(&msg, &mut peers);
                    }
                }
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => continue,
                    _ => break,
                },
            }
        }
        Ok(peers)
    }

    fn stop(&mut self) -> Result<(), TransportError> {
        let taken =
            self.advert.lock().map_err(|_| backend("advert lock poisoned"))?.take();
        if let Some(mut state) = taken {
            state.stop.store(true, Ordering::SeqCst);
            // Best-effort goodbye (TTL 0) so caches evict us promptly.
            if let Ok(sock) = bind_browse_socket(Duration::from_millis(50)) {
                let bye = MdnsDiscovery::build_response(&state.instance_tag, &state.addr, 0);
                let _ = sock.send_to(&bye, mdns_dest());
            }
            if let Some(h) = state.handle.take() {
                let _ = h.join();
            }
        }
        Ok(())
    }
}

impl Drop for MdnsDiscovery {
    fn drop(&mut self) {
        // Never leave a standing broadcast or a live thread behind.
        let _ = self.stop();
    }
}

/// The responder thread: answer PTR queries for our service and send an initial
/// unsolicited announcement so passive browsers learn about us. Exits promptly
/// when the stop flag is set.
fn responder_loop(sock: UdpSocket, instance_tag: String, addr: SocketAddrV4, stop: Arc<AtomicBool>) {
    // Announce once up front (unsolicited response to the group).
    let announce = MdnsDiscovery::build_response(&instance_tag, &addr, ADVERT_TTL);
    let _ = sock.send_to(&announce, mdns_dest());

    let mut buf = [0u8; 4096];
    while !stop.load(Ordering::SeqCst) {
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                let Some(msg) = dns::parse(&buf[..n]) else { continue };
                if msg.is_response() {
                    continue; // we answer questions, not other answers.
                }
                // Answer only if someone asked for our service by PTR.
                let asked = msg.questions.iter().any(|q| {
                    q.qtype == dns::TYPE_PTR && dns::names_eq(&q.name, SERVICE)
                });
                if asked {
                    let resp = MdnsDiscovery::build_response(&instance_tag, &addr, ADVERT_TTL);
                    // If the querier set QU, unicast back; also multicast so
                    // passive listeners refresh. Both are best-effort.
                    let _ = sock.send_to(&resp, from);
                    let _ = sock.send_to(&resp, mdns_dest());
                }
            }
            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => continue,
                _ => break,
            },
        }
    }
}

/// Fold the SRV/A/TXT/PTR records of one response into `peers`, de-duplicated by
/// instance tag. We only surface a peer once we have both a port (SRV) and an
/// address (A) — a hint you cannot dial is not a hint.
fn collect_peers(msg: &dns::Message, peers: &mut Vec<PeerHint>) {
    use std::collections::HashMap;

    // instance-name -> port
    let mut srv_port: HashMap<Vec<String>, u16> = HashMap::new();
    // host-name -> ip
    let mut a_addr: HashMap<Vec<String>, Ipv4Addr> = HashMap::new();
    // instance-name -> host-name
    let mut srv_host: HashMap<Vec<String>, Vec<String>> = HashMap::new();
    // instance-name -> tag (from TXT), falls back to the instance label.
    let mut txt_tag: HashMap<Vec<String>, String> = HashMap::new();

    for r in &msg.records {
        match &r.data {
            dns::Rdata::Srv { port, target, .. } => {
                srv_port.insert(r.name.clone(), *port);
                srv_host.insert(r.name.clone(), target.clone());
            }
            dns::Rdata::A(ip) => {
                a_addr.insert(r.name.clone(), *ip);
            }
            dns::Rdata::Txt(entries) => {
                for e in entries {
                    if let Some(v) = e.strip_prefix(b"tag=") {
                        txt_tag.insert(r.name.clone(), String::from_utf8_lossy(v).into_owned());
                    }
                }
            }
            dns::Rdata::Ptr(_) => {}
        }
    }

    for (instance, port) in srv_port {
        // Skip goodbyes (TTL 0 SRV) — but TTL lives on the record, and we keyed
        // by name, so re-scan records to check this instance's SRV ttl.
        let is_goodbye = msg.records.iter().any(|r| {
            r.name == instance
                && matches!(r.data, dns::Rdata::Srv { .. })
                && r.ttl == 0
        });
        if is_goodbye {
            continue;
        }
        let Some(host) = srv_host.get(&instance) else { continue };
        let Some(ip) = a_addr.get(host) else { continue };

        let lan_hint = format!("{ip}:{port}");
        let instance_tag = txt_tag.get(&instance).cloned().unwrap_or_else(|| {
            instance.first().cloned().unwrap_or_default()
        });
        let hint = PeerHint { lan_hint, instance_tag };
        if !peers.iter().any(|p| p.lan_hint == hint.lan_hint) {
            peers.push(hint);
        }
    }
}

/// Keep an instance tag to a single DNS label's worth of safe characters. The
/// tag is opaque and non-identifying; we only sanitize so it survives the wire.
fn sanitize_tag(tag: &str) -> String {
    let cleaned: String = tag
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(48)
        .collect();
    if cleaned.is_empty() {
        "postern".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_v4_hint_accepts_ipv4_and_rejects_junk() {
        assert!(parse_v4_hint("192.168.1.20:47001").is_ok());
        assert!(parse_v4_hint("not-an-addr").is_err());
        // A hostname (non-IPv4) is off-form for a LAN dial hint here.
        assert!(parse_v4_hint("desktop.local:47001").is_err());
    }

    #[test]
    fn sanitize_tag_strips_and_falls_back() {
        assert_eq!(sanitize_tag("abc-123_XYZ"), "abc-123_XYZ");
        assert_eq!(sanitize_tag("has spaces!!"), "hasspaces");
        assert_eq!(sanitize_tag(""), "postern");
        assert_eq!(sanitize_tag("///"), "postern");
    }

    #[test]
    fn collect_peers_round_trips_from_our_own_advertisement() {
        // Build exactly what our responder emits, parse it, and confirm browse's
        // collector recovers a dialable PeerHint. This exercises the full
        // advertise->wire->browse parse path with no socket involved.
        let addr = SocketAddrV4::new(Ipv4Addr::new(192, 168, 7, 42), 47001);
        let bytes = MdnsDiscovery::build_response("mytag", &addr, ADVERT_TTL);
        let msg = dns::parse(&bytes).expect("parse own advert");
        let mut peers = Vec::new();
        collect_peers(&msg, &mut peers);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].lan_hint, "192.168.7.42:47001");
        assert_eq!(peers[0].instance_tag, "mytag");
    }

    #[test]
    fn collect_peers_ignores_goodbye() {
        let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 5000);
        let bytes = MdnsDiscovery::build_response("bye", &addr, 0); // TTL 0
        let msg = dns::parse(&bytes).unwrap();
        let mut peers = Vec::new();
        collect_peers(&msg, &mut peers);
        assert!(peers.is_empty(), "a goodbye must not surface as a peer");
    }

    #[test]
    fn advertise_and_stop_do_not_error_even_without_multicast() {
        // The trait contract must hold in a sandbox: advertise + stop succeed
        // (best-effort), and a browse returns a snapshot (possibly empty).
        let mut d = MdnsDiscovery::new().with_browse_window(Duration::from_millis(120));
        let hint = PeerHint {
            lan_hint: "127.0.0.1:47001".into(),
            instance_tag: "sandbox-tag".into(),
        };
        d.advertise(&hint).expect("advertise best-effort ok");
        let _snapshot = d.browse().expect("browse returns a snapshot");
        d.stop().expect("stop ok");
    }

    /// Live end-to-end mDNS on the real LAN. Ignored by default because it needs
    /// a working multicast route (and no aggressive firewall). Run with:
    /// `cargo test -- --ignored mdns_live_roundtrip`.
    #[test]
    #[ignore = "requires a real multicast-capable LAN interface"]
    fn mdns_live_roundtrip() {
        let mut advertiser = MdnsDiscovery::new();
        advertiser
            .advertise(&PeerHint {
                lan_hint: "127.0.0.1:47999".into(),
                instance_tag: "live-test".into(),
            })
            .unwrap();
        std::thread::sleep(Duration::from_millis(200));

        let mut browser = MdnsDiscovery::new().with_browse_window(Duration::from_secs(2));
        let peers = browser.browse().unwrap();
        advertiser.stop().unwrap();
        assert!(
            peers.iter().any(|p| p.instance_tag == "live-test"),
            "should discover our own advertisement on the LAN"
        );
    }
}
