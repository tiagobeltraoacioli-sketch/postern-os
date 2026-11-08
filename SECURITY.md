# Security Policy

Coordinated vulnerability disclosure for **Postern Labs** — the websites
**posternlabs.com** and **posternpool.com**, the desktop / mobile / OS builds we
ship, and the open-source repositories behind them (including the ownerless
**Bloch-SIS-PoW** protocol).

This document is a disclosure policy and a safe-harbor statement. It is **not
legal advice** and creates no contract.

## Honest posture (read this first)

- **Mainnet beta, unaudited.** "Mainnet beta" is a designation, **not a security
  claim**. No third-party security audit has been completed on any Postern
  product or on the protocol; an audit is **contracted but not delivered**.
  Internal review and passing tests are not an audit.
- **The protocol is trivially forgeable right now.** The chain runs the
  **relaxed k=4 regime** of the Module-SIS PoW gate — proof-of-work is trivially
  forgeable. The single-jump k=8 hardening was activated at block 213,000 and then
  **reverted** (it raised difficulty ~4096x and low hashrate stalled the chain);
  it now re-activates as a **progressive k-ramp (k 5→6→7→8) with matched
  difficulty**, gated on hashrate headroom and miner coordination. The network is
  nascent, low-hashrate, and **51%-attackable**. Until those gates clear, **no
  security property is claimed**.
- **The coin is not a security and not an asset.** No token sale, no listing
  effort, no price, no returns, no custody — the protocol is **ownerless** and
  nobody (including Postern Labs) controls it. A **17% founder premine** (10-year
  cliff, 40-year vest, structurally passive) is disclosed in full. **Do not
  attach value to the coin.**
- **The websites are static and self-contained.** They ship no analytics, no
  trackers, no third-party scripts, fonts, or CDNs, and no covert telemetry. The
  interactive apps (below) connect only to endpoints you explicitly configure
  with your own credentials.

If you find that any published claim overstates the above, that itself is a
finding worth reporting.

## No bounty program

**There is no bug-bounty or paid-payout program at this time**, and this policy
does not promise money, swag, or any reward. What we offer is **coordinated
disclosure and public credit** (opt-in) for good-faith research. If a paid
program is ever created, it will be announced explicitly here — do not assume
one exists.

## Scope

In scope:

- **Websites:** posternlabs.com and posternpool.com — the static pages and the
  self-contained in-browser apps served under `/apps/*`, `/explorer/*`, and the
  Postern Store. Relevant classes: content/HTML injection, CSP weaknesses,
  supply-chain integrity of what the pages load, and any leakage of user input
  or API keys the apps handle.
- **Release artifacts & distribution:** integrity of published binaries, ISOs,
  and images, the SHA256SUMS lists, and the minisign signing flow (see
  *Verifying releases*).
- **Open-source repositories:** the code that builds the sites, apps, desktop,
  mobile, and OS images.
- **Protocol (Bloch-SIS-PoW):** consensus (GhostDAG-Q, reorg), the Module-SIS
  PoW gate, hybrid Falcon‖ML-DSA signatures, serialization/deserialization; the
  Coherence privacy layer (shielded pool, spend proofs) and network-layer
  metadata privacy (Dandelion++); node, wallet, keystore, RPC, and the
  attestation layer (L1–L3). **Privacy findings are explicitly in scope** —
  deanonymization, metadata leaks, address linkability, and any way the protocol
  could surveil or link users.

Out of scope:

- The **known** relaxed-regime PoW being forgeable — this is a documented,
  intentional gate, not a bug. A concrete exploit that goes **beyond** the
  documented gap (e.g. a break that persists after the k-ramp reaches k=8) is in
  scope.
- Gaps already documented as unaudited / claim-gated in the threat model. The
  documented gap is not a new finding; a concrete exploit of it is.
- Denial of service requiring implausible resources; findings only in
  third-party infrastructure or third-party APIs a user chooses to connect an
  app to (e.g. their own model/API provider).
- Reports from automated scanners with no demonstrated impact; missing security
  headers with no exploit path (report them, but rank them accordingly).

## Reporting a vulnerability

**Do not open a public issue, discussion, or merge request for a sensitive
finding.**

- Preferred: the repository's **private security advisory** flow, or
- Email **tiagobeltraoacioli@gmail.com** with `[postern-security]` in the
  subject. If you have our OpenPGP key, encrypt sensitive details.
  (See `/.well-known/security.txt` for the machine-readable contact.)

Please include: affected component (site URL, repo/commit, or product +
version), reproduction (a PoC is ideal), impact (what an attacker gains, under
what assumptions), any suggested fix, and whether you want public credit.

## What to expect

- **Acknowledgement:** we aim to reply within **~2 business days**.
- **Triage & updates:** we will confirm the issue, agree on severity, and keep
  you updated on remediation.
- **Fix & disclosure:** coordinated on a timeline that matches severity. We
  favor prompt, honest disclosure over silence.
- **Credit:** public credit if you want it; anonymity respected if you don't.

These are good-faith targets, not guarantees — Postern Labs is a small team.

## Safe harbor

We consider security research and vulnerability disclosure conducted in good
faith under this policy to be **authorized**, and we **will not pursue or support
legal action** against you for it, provided you:

- act in good faith to avoid privacy violations, data destruction, and service
  disruption;
- use only test accounts / your own data, and do not access, modify, or exfiltrate
  data that is not yours;
- do not run resource-exhaustion (DoS/DDoS), spam, social-engineering, or
  physical attacks;
- give us reasonable time to remediate before any public disclosure; and
- comply with applicable law.

This safe harbor is a statement of intent from Postern Labs; it cannot bind
third parties (hosting providers, upstream services, or other jurisdictions),
and it is **not legal advice**. If in doubt about whether an action is
authorized, ask first at the contact above.

## Verifying releases

Every release artifact is covered by a signed `SHA256SUMS` list. **Both checks
are required — neither is optional:**

```sh
# 1. Checksum — every file you downloaded must verify against the signed list.
sha256sum -c SHA256SUMS

# 2. Signature — proves the checksum list itself was published by Postern.
minisign -Vm SHA256SUMS -P RWTSe98wfKKHuVRDnywuQmH/cMyP/HNuD/hFFLQeKdQeAHENliqJpmKs
```

The checksum proves each file is intact; the signature proves the list came from
us. The minisign public key is:

```
RWTSe98wfKKHuVRDnywuQmH/cMyP/HNuD/hFFLQeKdQeAHENliqJpmKs
```

It is published in more than one independent place (in the release notes, as a
`.pub` file next to the artifacts, and here) so you can cross-check it. A signed
image is **not** attestation of security — verify integrity, then evaluate and
reproduce the build; don't protect real secrets with beta software yet.

## Development security practices

- **Supply chain (repos):** `Cargo.lock` committed; the PQ-crypto fork is
  vendored (`crates/pqcrypto-internals`) so the workspace is self-contained.
  `cargo deny check` (`deny.toml`) enforces permissive licenses (no copyleft),
  no external git deps, and RUSTSEC advisories — run in CI.
- **Supply chain (websites):** the static pages load **zero** third-party
  scripts, styles, fonts, or trackers; every asset is first-party or inline, so
  there is nothing to subresource-integrity-pin. Marketing pages ship a strict
  `Content-Security-Policy` with `connect-src 'none'`; the interactive apps
  restrict `connect-src` to the specific endpoints they need.
- **Secret scanning:** `gitleaks` runs in CI. Rotate any credential that ever
  touches a shell or history.
- **Reproducible builds & signing:** release artifacts are minisign-signed; the
  node image targets byte-reproducibility (L1); OS images are reproducible by
  construction.
- **Least privilege:** the node runs hardened (container hardening / NixOS
  `services.bloch` systemd sandbox); keystores are encrypted (Argon2 + AEAD).
- **Fuzzing:** coverage-guided fuzz targets for untrusted-input parsers; new
  parsers of untrusted bytes get a target.

## No claims before their gate

We do not claim any security or privacy property before its audit gate clears.
No "100% private" and no "secure" claim, ever, before an external audit.
