<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Postern Labs
Architect A3 (fable5) — Cloud / Chiostro gap analysis. READ-ONLY audit; no code changed.
-->

# Postern Cloud / Chiostro — gap analysis (what is MISSING vs claims)

**Scope:** the Chiostro confidential-VM profile (`os/cloud.nix` + `os/attested.nix`),
the attestation path (`crates/postern-seal-companion` — SEV-SNP fetch + AMD-root
verify, TDX PCS/DCAP parser), the hosted services (license verification, relay,
managed-node control plane), and the live endpoint
`postern-cloud-demo.fly.dev/v1/posture`.

**Verdict up front:** the site is **honest**. Every load-bearing claim I checked
against the code holds: "unbuilt and unbooted", "a promise, not a proof", "checked
only against an offline report fixture — never on real SEV-SNP hardware", "a TDX
parser that stays fail-closed (never returns Genuine)". No overclaims found. The
gap is not honesty — it is that a *verifiable confidential VM* requires (a) a Nix
host to build the image, (b) SEV-SNP/TDX hardware to boot and attest it, and
(c) a few code items that no amount of the above supplies. Those three buckets are
quantified at the end.

## The critical distinction the reader must not miss

"Cloud edition" is **two unrelated systems** sold under one name, and the site
correctly separates them:

1. **Chiostro** — the confidential VM you can *verify* (`os/cloud.nix` +
   seal-companion). The attestation crypto is real code. **It has never been built
   or booted, and never run on TEE hardware.** This is where all the attestation
   substance lives, and none of it is proven above offline vectors.
2. **Managed services** (`enterprise/cloud/`) — hosted license verification, a
   comms relay, and managed-node orchestration. These are running Node.js
   reference prototypes. **Only the license-verification service is live**
   (`postern-cloud-demo.fly.dev`). It does Ed25519 signature verification but
   **zero TEE/attestation crypto** — it is not, and does not claim to be, the
   confidential VM. The managed-node orchestrator spins up **no real
   infrastructure** (`simulated: true`).

The live fly.dev endpoint is #2's license service, not #1. A reader who conflates
"there's a live demo" with "the TEE is real" would be wrong; the site does not
invite that error.

## Proof-tier ladder (used in the table)

- **T0** design / prose only
- **T1** unit- / offline-vector-tested (synthetic or vendored fixture; no hardware)
- **T2** image builds and boots (QEMU or real host) — nothing here reaches T2
- **T3** hardware-attested: runs in a real SEV-SNP/TDX guest, a live quote verifies
- **T4** externally audited / production

Nothing in Chiostro is above **T1**. The live license service is a deployed T1
(reference prototype, unaudited).

---

## Structured gap list

### A. Attestation verifier — SEV-SNP (`crates/postern-seal-companion/src/snp.rs`)

| # | Capability | Status | What's missing | Proof tier | Priority | Effort |
|---|---|---|---|---|---|---|
| A1 | SNP report verify: VCEK→ASK→ARK chain to pinned AMD root + field checks (measurement / HOSTDATA / report_data / TCB floor / VMPL / debug-policy), fail-closed | **DONE** (code) | Only ever run against a *vendored* Milan report+VCEK fixture (`testdata/`), never a quote from hardware Postern launched | T1 | P1 | done; needs T3 |
| A2 | AMD-KDS CRL freshness + revocation (`check_kds_crl` / `verify_snp_report_with_crl`), pinned-ASK-verified, `nextUpdate` enforced | **DONE** (code), opt-in | Tested only vs a **synthetic** AMD-style CRL; **base `verify_snp_report` still accepts a since-revoked VCEK** (pinned roots are AMD's long-lived 2020 keys); real CRL fetch is out-of-band and unbuilt | T1 | P1 | S (wire the fetch) |
| A3 | Guest-side live report fetch (`request_bound_evidence` / `request_ext_report` / `request_raw_report`) — real virtee/sev ioctls on `/dev/sev-guest`, channel binding wired in | **SCAFFOLD** (compiles everywhere, fail-closed off-TEE proven) | **Never executed inside a real SEV-SNP guest** — the C2→C3 "vector-tested ≠ attested" lift. Needs SEV-SNP hardware (GCP N2D Milan per runbook) | T1 | **P0** | M (hardware run) |
| A4 | Channel binding `report_data = SHA-256(nonce‖pubkey)` (`binding.rs`), TEE-independent | **DONE** (code, tested) | nothing | T1 | — | done |
| A5 | Negative controls on hardware (stale nonce, MITM pubkey, wrong generation, measurement-off-by-bit, TCB floor, debuggable policy) | **MISSING** | Runbook §7 lists them; none executed (no hardware) | T0 | P1 | M (with A3) |
| A6 | Release-manifest pipeline producing the expected `{D, R, M[shape], P, min-tcb}` the verifier pins | **MISSING / design** | No `sev-snp-measure` pipeline; `M`/`P` are hand-supplied per runbook. "Expected values only as good as the manifest that produced them" | T0 | P1 | M |

### B. Attestation verifier — Intel TDX (`crates/postern-seal-companion/src/tdx.rs`)

| # | Capability | Status | What's missing | Proof tier | Priority | Effort |
|---|---|---|---|---|---|---|
| B1 | DCAP v4 TD-quote structural parser (header + TD 1.0 body, strict bounds) + field comparison | **DONE** (code, tested) | authenticates nothing by design (a forged quote parses fine) | T1 | P2 | done |
| B2 | Full DCAP chain verify: PCK→Intel processor CA→pinned Intel root, QE-report binding, QE-report + quote ECDSA sigs, CRL freshness, TCB-SVN floor (feature `tdx-verify`) | **SCAFFOLD** — crypto real, **fail-closed** (never `Genuine`) | **`PINNED_INTEL_SGX_ROOT_CA_DER` is an empty placeholder** — a human must paste Intel's real root DER; until then it can never authenticate. Exercised only vs a **synthetic** anchor root | T1 | P2 | **S** (paste one DER) then M (test) |
| B3 | Intel TCB-info / QE-identity JSON collateral **signature** verification (Intel TCB signing cert) | **MISSING** | Not folded in; freshness leans on CRL `nextUpdate` only. Documented, not silently skipped | T0 | P2 | M |
| B4 | TDX 1.5 body (`MRSERVICETD` + 2nd TCB SVN), Azure/paravisor surfacing | **MISSING** | 1.5 length deliberately fails the strict 1.0 check; no 1.5 decode | T0 | P3 | M |

### C. Seal-gate transport + binaries

| # | Capability | Status | What's missing | Proof tier | Priority | Effort |
|---|---|---|---|---|---|---|
| C1 | Seal-gate wire codec (`gate.rs`) — magics, hard per-field caps, no-alloc-before-check, trailing-byte rejection | **DONE** (code, hostile-input tested) | nothing (TEE-independent, default build) | T1 | — | done |
| C2 | `postern-seal-gate` guest binary — inline SNP ioctls, fail-closed off Linux/off-TEE | **SCAFFOLD** | never run on hardware; duplicates the `snp.rs` library ioctls (flagged follow-up to dedupe) | T1 | P1 | M (hardware) |
| C3 | `postern-seal-verify` client CLI — the §4.1 handshake the runbook drives | **SCAFFOLD** (feature-gated `sev-snp`) | never driven end-to-end against a live gate | T1 | P1 | M (hardware) |

### D. Chiostro CVM profile (`os/cloud.nix`, base `os/attested.nix`)

| # | Capability | Status | What's missing | Proof tier | Priority | Effort |
|---|---|---|---|---|---|---|
| D1 | Confidential-VM guest profile: verity-sealed rootfs, seal-gate as sole pre-attestation listener, WG-only desktop/SSH, hardening spine, headless wayvnc-in-tunnel | **SCAFFOLD / DESIGN** | Written on a non-Nix host — **NOT built, NOT booted**. repart/verity/UKI options drift across nixpkgs; needs a Nix host to build and real SEV-SNP/TDX to boot | T0→needs T2 | **P0** | L |
| D2 | Base attested image (`attested.nix`): erofs + dm-verity + UKI + measured boot — Chiostro's dependency | **SCAFFOLD / DESIGN** | same non-Nix caveat; the `os_roothash`/`M` the verifier pins come from here and are unproduced | T0 | **P0** | L |
| D3 | In-guest LUKS `/persist`: TEE-random key, TPM2-sealed to measured boot (PCR 0+7) | **SCAFFOLD** | first-boot provisioning unvalidated; TPM2-seal behaviour on a CVM launch measurement is per-provider and untested; **key custody is the open item flagged in spec §1.6** | T0 | P1 | M |
| D4 | In-guest WireGuard keygen (TEE-random, host never sees private half) + deny-only client allowlist ingestion | **SCAFFOLD** | untested (never booted); depends on D3 mount ordering | T0 | P1 | S |
| D5 | Per-provider firmware / measurement / HOSTDATA details (GCP N2D clean path; Azure vTPM/paravisor) | **MISSING** | Azure needs a vTPM/paravisor `report_data` adapter that does not exist; runbook says "do not claim Azure end-to-end" | T0 | P2 | L |
| D6 | Fleet key release via org-hosted KBS (Trustee) gated on a Trusted verdict | **MISSING / design** | mentioned in profile comment; no code | T0 | P3 | L |
| D7 | Secure-Boot signing (Microsoft-endorsed or enrolled keys) for the CVM image | **MISSING** | signed-shim planned not shipped (site downloads page confirms) | T0 | P3 | M |

### E. Hosted managed services (`enterprise/cloud/`)

| # | Capability | Status | What's missing | Proof tier | Priority | Effort |
|---|---|---|---|---|---|---|
| E1 | **License-verification service** (`license-service.mjs`) — **LIVE** at fly.dev. Real Ed25519 chain verify server-side + revocation working-set + vendor-signed CRL publish/verify (monotonic version). Holds only vendor PUBLIC key; **refuses to start without it** (fail-closed). Honest `/v1/posture` disclosure returned inline | **DONE** (reference prototype, deployed) | In-memory stores (no durable backend deployed); **unaudited**; no TEE/attestation crypto at all (correctly — it is a licensing convenience, not the CVM); staging not production | T1 (deployed) | P2 | S→hardening |
| E2 | Comms **relay** (`relay-service.mjs`) — transport-only, opaque E2EE blobs, sealed-sender, deliver-then-drop, counts-only logging | **SCAFFOLD** | **NOT deployed** (entrypoint default `POSTERN_SERVICE=license`); in-memory queues; no crypto (by design — "carries E2EE bodies opaquely but sees routing metadata") | T1 | P3 | S |
| E3 | Managed-node **control plane** (`orchestrator.mjs`) — tenant isolation, license-bound lifecycle (revoke⇒deprovision) | **SCAFFOLD** | **Spins up NO real infrastructure** — every node is `simulated: true` absent an injected operator `driver`; `provision()` records intent only. Matches site's "promises, does no cryptography" | T0/T1 | P3 | L (needs a real driver) |
| E4 | Cloud OCI image (`enterprise/cloud/image/` — Containerfile + optional `cloud-image.nix`) | **SCAFFOLD** | "reproducible-by-design, NOT reproduced"; Nix path written on non-Nix host, unbuilt; not hardened/audited | T0/T1 | P3 | M |

---

## Live endpoint coverage (`postern-cloud-demo.fly.dev`) — measured

Probed 2026-07-13. This is service E1 (license), not the CVM.

| Path | Method | Live result | Notes |
|---|---|---|---|
| `/healthz` | GET | 200 | up |
| `/v1/posture` | GET | 200 | full structured privacy disclosure, `status: reference-prototype/unaudited` |
| `/v1/verify` | POST | 200 | real Ed25519 chain verify; empty body → `{state:invalid, reason:malformed-master}`; every answer carries an honest `disclosure` + vendor-key fingerprint `fab36e2acbe1810e` |
| `/v1/vendor-key` | GET | 200 | serves vendor **public** key `iW52…` — "holds NO private key" |
| `/v1/revocations` | GET | 200 | public unsigned working-set (empty) |
| `/v1/crl` | GET | **404** | route exists in code; not reachable on the deployed build (likely older image or trimmed router) — minor drift worth noting |
| `/`, `/v1/send`, `/v1/attest` | GET | 404 | relay/attest not on this deployment (expected — license service only) |

Assessment: the live demo does exactly what the site says — a hosted
license/revocation check that discloses its own privacy regression vs offline
verification, holds no signing key, and fails closed without the vendor key. It is
**not** an attestation or TEE endpoint and never presents itself as one. Only
observable drift: `/v1/crl` 404s on the deployed build though the code implements it.

---

## The gap to a real verifiable confidential VM, quantified

Three buckets, none substitutable for another:

**1. Needs a Nix host (build) → moves T0 to T2 "it builds":**
`os/attested.nix` (D2) and `os/cloud.nix` (D1) must build into an actual image;
first-boot LUKS (D3) and WG keygen (D4) must be validated; the OCI image (E4).
None have been built — the dev host has no Nix. This also produces the `os_roothash`
/ launch-measurement `M` the verifier pins (A6, D2).

**2. Needs SEV-SNP / TDX hardware (boot + attest) → T2 to T3:**
Live report fetch (A3) and its negative controls (A5); driving the gate + verifier
end-to-end (C2, C3); confirming TPM2-seal on a real launch measurement (D3);
per-provider measurement/HOSTDATA (D5). Runbook `HARDWARE-RUNBOOK.md` is the
procedure; GCP N2D Milan is the clean first target. Azure needs the missing
vTPM/paravisor adapter (D5) before it can be claimed.

**3. Missing entirely, hardware won't supply (code / process gaps):**
- **B2** — paste Intel's real root DER (one line unblocks TDX authentication).
- **B3** — Intel TCB-info / QE-identity JSON collateral signature verification.
- **A2** — an out-of-band AMD-KDS CRL fetcher (crate does no network I/O by design);
  and note **base `verify_snp_report` accepts a revoked VCEK** unless the opt-in
  CRL path is used — a production caller must use `verify_snp_report_with_crl`.
- **A6** — the signed release-manifest pipeline (`sev-snp-measure`) that yields the
  expected `{D,R,M,P,min-tcb}`.
- **D5** — Azure vTPM/paravisor `report_data` adapter.
- **D6** — KBS/Trustee fleet key release gated on a Trusted verdict.
- **D7** — Secure-Boot signing.
- **E3** — a real operator `driver` so managed nodes stop being `simulated`.
- **T4** for everything — no external audit exists anywhere in this stack.

## Honesty verification (the site's own claims, checked)

All accurate:
- "unbuilt and unbooted … code and profiles, not a running, verified TEE" — matches D1/D2 non-Nix caveat and the seal-companion "never run on hardware we launched" notes.
- "SEV-SNP report-fetch + AMD-root verify … checked only against an offline report fixture — never on real SEV-SNP hardware" — matches A1/A3.
- "a TDX parser that stays fail-closed (it never returns Genuine)" — matches B2; the pinned root is literally `&[]` and `verify_td_quote` cannot reach `Genuine`.
- managed-node "promises, does no cryptography" — matches E3 (`simulated:true`, no crypto). Nuance: the *license* service (E1) that is actually live **does** do signature-verification crypto; the site attributes crypto-absence to the managed-**node** path, which is correct, and describes the license endpoint separately and accurately.
- "a promise, not a proof" for hosted relay metadata — matches E2's own `promiseNotProof` posture string.

No overclaim found. The one factual nit is operational, not marketing: `/v1/crl`
is implemented in code but 404s on the deployed build.
