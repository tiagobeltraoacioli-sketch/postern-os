<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# postern-pairing-transport-lan

> ⚠️ **SCAFFOLD — not a secure, audited, or deployed system.**

A **real LAN transport + discovery** for the [`postern-pairing`](../pairing)
scaffold. It provides live implementations of the two network seams that crate
defines behind traits — replacing the in-memory `LoopbackPair` / `NullDiscovery`
stubs for actual mobile↔desktop use on the same subnet.

This is a **new, standalone crate**. It carries its own empty `[workspace]`
table, so it builds and tests in isolation and does **not** join the ancestor
`bloch-protocol` workspace. It **does not modify** `integration/pairing`; it only
depends on it (path dependency) to implement its traits.

## What it provides

| Seam (in `postern-pairing`) | Implementation here |
| --- | --- |
| `transport::Transport` | `TcpTransport` / `TcpTransportListener` — a length-prefixed (`u32` BE) framed TCP pipe: message boundaries, a **bounded** frame size (`DEFAULT_MAX_FRAME_LEN` = 256 KiB), read/write **timeouts**, and a **clean close**. |
| `transport::Discovery` | `MdnsDiscovery` — an mDNS / DNS-SD advertiser + browser for `_postern-pair._tcp.local` on the link-local multicast group. Hand-rolled DNS wire codec (`dns.rs`), no resolver dependency. |

The only third-party dependency is **`socket2`** (rust-lang org; the socket layer
under mio/tokio), used solely to set `SO_REUSEADDR`/`SO_REUSEPORT` and IPv4
multicast membership so an mDNS responder can coexist with the OS resolver on
`:5353`. Everything else is `std`. No async runtime, no framework.

## Rails (non-negotiable)

- **LAN-ONLY.** Multicast is the reserved link-local group `224.0.0.251:5353`
  (RFC 6762); TCP dials only the address discovery handed it. **No cloud, no
  relay, no Tor, no internet path, no telemetry, no phone-home.**
- **The transport is a DUMB PIPE.** It carries `postern-pairing`'s already-sealed,
  length-prefixed frames as opaque bytes. **All crypto** — the PQ-hybrid KEM, the
  mandatory QR-pin + 6-digit SAS, the XChaCha20-Poly1305 channel with anti-replay
  — lives in the pairing crate. This layer authenticates nothing and decrypts
  nothing.
- **Discovery is a metadata leak, opt-in, off by default.** Advertising tells the
  subnet a Postern endpoint is present; that is why `postern-pairing` ships
  `NullDiscovery` as the default. The advertisement is **minimal** — a protocol
  version and an opaque, rotating instance tag. **No wallet address, no identity,
  no account.**
- **Discovery ≠ authentication.** A browsed peer is an untrusted dial hint; an
  evil twin can advertise too. Only the QR-pin + SAS ceremony authenticates the
  peer — this layer just points it at a socket.
- **Scaffold, unaudited** — nothing here is built, secure, attested, or deployed.
- **A rooted/malware endpoint (A5) defeats the whole feature.** Ring-0 on either
  device reads the session key from RAM and forges the approval UI; a byte pipe
  cannot defend that.
- **The coin (BLCH) is not a security** and is not involved. Personal use is free
  forever — no token, no login. The community mobile edition is
  **"Postern for postmarketOS — community edition"**, never "Postern OS"; the
  assurance name is never "BABA YAGA".

## Build & test (offline)

```sh
cargo build            # std + socket2 + postern-pairing (path); builds offline
cargo test             # 20 tests: TCP round-trip, framing, timeouts, DNS codec,
                       #            mDNS collector, and the full ceremony over TCP
cargo test -- --ignored mdns_live_roundtrip   # live multicast self-discovery
```

### Which paths are exercised

- **Socket path (fully tested):** a real localhost TCP round-trip preserving
  message boundaries; oversize-frame refusal on both send and receive; timeout →
  `WouldBlock`; clean close → `Closed`; and the **entire pairing ceremony driven
  over `TcpTransport`** (`demo::pair_over_tcp`), carrying a real `PairingInit` and
  an encrypted channel frame end to end.
- **Loopback path (offline):** `postern_pairing::demo::pair_and_talk` runs the
  same ceremony over the in-memory stub, unchanged — the new types share the
  traits.
- **mDNS wire codec (fully tested):** query/response encode↔parse round-trips for
  all four DNS-SD record types, goodbye (TTL 0) handling, truncation safety, and
  a pointer-loop guard.
- **Live mDNS (`#[ignore]`d):** advertise + browse over real multicast. It
  succeeds via loopback multicast on a multicast-capable host (self-discovery),
  but genuine **cross-device** discovery needs a real LAN with multicast routed
  and no aggressive firewall — run it there.

## Layout

```
src/lib.rs    crate root, rails, re-exports
src/tcp.rs    TcpTransport / TcpTransportListener  (impl Transport)
src/mdns.rs   MdnsDiscovery                        (impl Discovery)
src/dns.rs    minimal DNS/mDNS/DNS-SD wire codec
src/demo.rs   full ceremony over real localhost TCP (pair_over_tcp)
```

Dual-licensed under **MIT OR Apache-2.0** (see `LICENSE-MIT`, `LICENSE-APACHE`).
