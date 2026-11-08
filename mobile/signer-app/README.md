<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Postern phone-as-signer — reference driver

A **reference UI + driver** for the phone side of Postern's phone-as-signer flow.
It is a framework-free web UI backed by a thin Node bridge that drives the real
[`postern-mobile-signer`](../signer) engine. It **reimplements no crypto**: every
consequential answer — the WYSIWYS sentence, the consequence tier, the replay
guard, the hybrid Falcon‖ML-DSA signature — comes from the frozen protocol/pairing
crates through `postern-mobile-signer`.

> ### This is a reference driver, not a shipped phone app.
> The Postern mobile OS image is **UNBOOTED**. This runs on a workstation to
> exercise and demonstrate the phone-side approval UX. The signing key never
> leaves the device, but on the community edition this is a **software keystore —
> not a hardware wallet**; a rooted / jailbroken / malware-infected phone can
> read the key from RAM and forge the approval screen. Every signature requires
> **per-sign user presence** — there is no blanket auto-approve. Unaudited
> scaffold. This is **not** "Postern OS" (the community edition is "Postern for
> postmarketOS — community edition"). The coin is **not a security**. Nothing
> here is "100% private/secure".

## What it demonstrates (Design §3.3 / §6)

1. **Pair** — scan/paste the desktop's QR payload, then compare the **6-digit
   SAS** on both screens (differ ⇒ possible interceptor ⇒ abort). The real
   ceremony is the PQ-hybrid `postern-pairing` handshake; here the SAS is derived
   deterministically from the payload so the compare step is faithful.
2. **Receive a sign request** — a desktop-simulator panel (stand-in for the
   key-less terminal) sends a **genuine request frame**. The phone engine parses
   the *actual bytes it would sign* and renders WYSIWYS.
3. **Approve with WYSIWYS + consequence tier** — the card shows the plain-language
   sentence, the tier (`SilentReadOnly` / `SingleTap` / `ExplicitReview`), a
   fund-movement flag, the peer device, and a confirmation fragment to compare
   with the desktop.
4. **Per-sign presence** — biometric / device-PIN, bound to *that request's own
   nonce*. Approve → the engine returns the hybrid signature (public); decline →
   nothing is signed and the replay guard never advances.
5. Optional **revocable single-tap grant** for the reversible login tier only —
   never covers a value transfer (the engine refuses).

## Run

```sh
# 1) Build the engine driver (calls postern-mobile-signer; no crypto here):
cargo build --manifest-path signer-cli/Cargo.toml     # or: npm run build-engine

# 2) Start the local host (binds 127.0.0.1:8787):
node bridge/server.js                                  # or: npm start
# open http://127.0.0.1:8787
```

If `signer-cli` is **not** built, the bridge drops into an explicit **preview**
mode: it drives the UI so the flow is inspectable, but it **signs nothing and
fabricates no signature**, and says so on every reply. Build the engine for real
WYSIWYS output and a real signature.

## Layout

| Path | Role |
|---|---|
| `web/` | framework-free UI (`index.html`, `app.js`, `styles.css`) — no deps, no build step |
| `bridge/server.js` | dependency-free HTTP host (serves `web/`, forwards `POST /api`) |
| `bridge/signer-bridge.js` | spawns `signer-cli` and speaks its line-JSON protocol; honest preview fallback |
| `signer-cli/` | Rust stdio JSON driver that holds a real `MobileSigner` + key-less `DesktopRequester` and calls `postern-mobile-signer` |

## Verify

```sh
npm run check                                          # node --check on the JS
cargo build --manifest-path signer-cli/Cargo.toml      # builds the engine driver
```

## What crosses the boundary

Only **public** data ever leaves the engine over the JSON bridge: the address,
the identity public key, the signature, and the digest that was signed. The seed
and secret key are structurally unable to appear there — the signer seam yields
only public outputs, and the protocol's wire types have no key field.

Dual-licensed under MIT OR Apache-2.0.
