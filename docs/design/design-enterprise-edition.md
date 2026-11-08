# Postern Enterprise Edition — technical design

**Role:** designer/architect. **Status:** design of record + working reference console (Consiglio). Unaudited.

> ## ⚠ Honesty preamble — read first
>
> - **Unaudited.** No primitive, protocol, or flow here has had an external security review. Treat everything as pre-audit engineering.
> - **Wallet-as-login is novel, not battle-tested.** Challenge-response auth off a PQ wallet key is a sound idea, but it is *not* OIDC/SAML, it has no deployed track record at org scale, and the interesting failure modes (device-key theft under coercion, directory-availability collapse, recovery-quorum social engineering) are real and called out below.
> - **Not legal/compliance advice.** The LGPD/GDPR/CCPA controls *enable* a compliance program; a DPO + admitted counsel *make* one. Every counsel-owned decision is flagged **LEGAL DETERMINATION REQUIRED (DPO/counsel)**, consistent with `docs/specs/POSTERN-ENTERPRISE.md`.
> - **Grounded, not aspirational.** This design describes what the Consiglio prototype (`apps/postern-enterprise/index.html`) actually implements today, what the personal wallet/identity stack (`crates/postern-*`, `docs/specs/POSTERN-IDENTITY.md`) actually provides, and — separately and explicitly — what backend is *missing* to make Enterprise real. Prototype stand-ins are labeled as such everywhere.

---

## 0 · Source foundations (what already exists)

| Foundation | Where | What it gives Enterprise |
|---|---|---|
| **PQ wallet** | `crates/postern-sdk/src/wallet.rs` → `bloch_mobile::WalletCore` (`mobile/core`) | BIP39 seed → **hybrid Falcon-1024 ‖ ML-DSA-65** keypair; `sign_hex` / `public_key_hex`; domain-separated diversified derivation. The identity primitive. |
| **Wallet-as-login ceremony** | `docs/specs/POSTERN-IDENTITY.md` (codename **Chiave**, `apps/postern-login/index.html`) | The *personal* challenge-response login: passphrase → Argon2id → unlock → derive `m/login/d` → sign fresh challenge → verify both signatures. Enterprise reuses this *machinery* under a different authority. |
| **Canonical seal + KDF + attestation transcript** | `crates/postern-core/src/lib.rs` | One AEAD seal (XChaCha20-Poly1305, versioned, context-bound, key-committing), Argon2id KDF, and the **attestation transcript** the device signs to prove genuine build (`seal::attestation_transcript`). |
| **Passkey/credential core** | `crates/postern-keys/src/lib.rs` | ES256/WebAuthn assertion signing + `to_vault_record` identity-binding pattern (classical; useful only if bridging to WebAuthn RPs). |
| **Vault** | `crates/postern-vault` | Argon2id + XChaCha20-Poly1305 at-rest sealing for secrets (the `corp/vault` KEK target). |
| **Consiglio reference console** | `apps/postern-enterprise/index.html` (single file, strict CSP) | Working org bootstrap, RBAC/ABAC, Chinese-Wall editor, provision/offboard ceremonies, **real Shamir GF(256)** escrow, hash-chained audit, transparency panel. Browser stand-ins for the PQ + TEE + OS layers (labeled in-app). |
| **Enterprise spec** | `docs/specs/POSTERN-ENTERPRISE.md` | The design of record this document builds a concrete protocol on top of. |

**Key architectural fact that shapes everything:** the personal wallet is *self-sovereign* (seed = root, no admin, seed-or-nothing recovery). Enterprise **deliberately trades some of that away** — the org is the identity authority and the data controller — while refusing to trade transparency, proportionality, dual-control, and auditability. That tension is the product, stated honestly (§2 of the spec).

---

## 1 · Wallet-as-login — a concrete auth protocol

### 1.1 What "wallet-as-login" means here

The Postern PQ wallet key becomes an **org SSO/identity primitive** by using the wallet's hybrid `sign()` in a challenge-response ceremony, binding the public key to an org directory identity. It is **not** OIDC or SAML — it is a device-bound, post-quantum, phishing-resistant local authenticator. Where the org needs OIDC/SAML (web apps, existing SPs), Enterprise must **bridge** (§1.7), and the bridge is where classical, non-PQ, phishable surface re-enters — stated plainly.

Critical distinction from personal Chiave: **corporate login is not the self-custody wallet.** It reuses Chiave's machinery (TEE-held signing key, domain-separated derivation, fresh-challenge ceremony) but the **device key is generated on the device at enrollment and *certified by the org*, not derived from a user seed** (spec §3.1, §3.3). There is deliberately no user-exportable seed for corporate data — recovery is escrow, not a seed phrase (§2 governance).

### 1.2 Key hierarchy

| Key | Alg | Held by | Role |
|---|---|---|---|
| **Org root key** | Falcon-1024 ‖ ML-DSA-65 | Offline/HSM, usable only under governance quorum | Signs the directory signing key + the quorum public set. Rotated ceremonially. |
| **Directory signing key** | hybrid | Directory service (self-hosted) *or* delegated to a federated IdP trust anchor | Signs **enrollment certificates** and **short-lived login assertions**; countersigns policy docs. |
| **Per-user device key** | hybrid, per device | Employee device **TEE**, non-exportable | Signs the login challenge. Generated on-device at enrollment; org certifies it, never holds it. |
| **User data keys** | symmetric (FBE/vault KEKs) | Derived on-device from a TEE random root (`corp/profile`, `corp/vault`), released only during a valid session | Encrypt the corporate profile + entitled project volumes. |
| **Escrow recovery key** | symmetric root | **Nobody, whole** — Shamir M-of-N across the governance quorum | Org-side recovery of *company* data + account restore (§2.3). |

> **Falcon-half honesty (from `POSTERN-IDENTITY.md`):** `bloch-crypto` derives **ML-DSA-65 deterministically** from a seed, but **Falcon keygen is currently random** (floating-point Gaussian sampling). So the **ML-DSA anchor is the durable identity** and the Falcon half is device-resident, sealed in the keystore, re-enrolled on restore by the anchor cross-signing the fresh hybrid public key. For Enterprise this is *cleaner* than for personal: there is no seed to derive from anyway — the whole device key is fresh-at-enrollment and org-certified, so both halves are simply generated on-device and the public key is certified.

### 1.3 Enrollment protocol (key → identity binding)

```
Admin (audited)                 Directory service              Employee device (TEE)
──────────────                  ─────────────────              ─────────────────────
1. create directory entry
   {user_id, org_unit, role,
    attrs, policy_version}
2. issue one-time enroll token  ──────── QR / code, short TTL, single-use ───────▶
                                                                3. TEE generates fresh
                                                                   hybrid keypair
                                                                   (Falcon ‖ ML-DSA)
                                                                4. build attestation:
                                                                   seal::attestation_transcript(
                                                                     os_roothash, measurement, nonce)
                                                                   signed by device key
        ◀───── {device_pubkey, attestation_evidence, enroll_token} ─────────────
5. verify token (unused, live)
6. verify attestation
   (measured boot, genuine build)
7. issue ENROLLMENT CERTIFICATE:
   sign(directory_key, {
     user_id, device_id,
     device_pubkey, role, attrs,
     policy_version, not_after})
        ─────────────────── enrollment cert ────────────────────────────────────▶
                                                                8. device seals cert +
                                                                   TEE key handle;
                                                                   escrow ceremony runs (§2.3)
```

The enrollment certificate is the **key→identity binding**: it cryptographically ties a specific TEE-resident public key to a directory identity, role, and attributes, signed by the org's directory key (which chains to the org root). This mirrors the `Credential::to_vault_record` discipline in `postern-keys` — identity and key travel in **one signed record** so they cannot be recombined.

### 1.4 Login ceremony (challenge-response, per session)

Login requires **two proofs**, and the OS session opens only if *both* verify:

```
Device                                        Verifier (local session manager)
──────                                        ────────────────────────────────
1. user unlocks TEE-gated device key
   (passphrase → Argon2id, or biometric
    gate in front of the TEE key — never
    the root of trust; POSTERN-IDENTITY §)
                                              2. issue fresh challenge:
   ◀──────────────────────────────────────      {v:"postern:login:v1",
                                                  nonce(32B), device_id, ts}
3. sign challenge HYBRID
   (Falcon ‖ ML-DSA) with device key
   ───── {sig_falcon, sig_mldsa} ─────────▶  4. verify BOTH sigs against the
                                                enrolled device_pubkey in the cert
                                              5. verify enrollment cert chain
                                                (directory_key → org_root)
   ───── present short-lived directory ────▶  6. verify directory assertion
         assertion (mins–hours TTL,             (org still vouches NOW), TTL not
         OIDC-token-like)                        expired, policy_version current
                                              7. BOTH pass → open session:
                                                 release FBE + vault KEKs;
                                                 volume-key broker re-checks
                                                 entitlement per mount
```

- **Proof 1 (device key)** answers *"is this the enrolled hardware + user?"* — this is the phishing-resistant, PQ, non-exportable half. It is what keeps a stolen IdP session from becoming a Postern session.
- **Proof 2 (directory assertion)** answers *"does the org still vouch for this account right now?"* — short-lived so revocation takes effect within one TTL (§2.4).
- **Domain separation** is load-bearing: the challenge carries the `postern:login:v1` tag so a login signature can never be replayed as a wallet-spend or courier-handshake signature (the transcript-tagging discipline from `postern-core::seal`). The `m/login` path is *never* the `m/spend` path — authenticating never exposes a funds key.

### 1.5 Recovery

Personal Postern: **seed-or-nothing.** Enterprise: **escrowed recovery under dual control** — because the corporate data root is a TEE random root with no user-memorable seed. At enrollment the data root is wrapped under the user's escrow recovery key, which is immediately Shamir-split M-of-N to the governance quorum and the whole key destroyed. Recovery = quorum reconstructs the escrow key → unwraps the data root → re-seals to a new device or successor (§2.3). **Honest limit:** lose quorum *and* device and corporate data is as gone as a lost personal seed — the org's escrow governance is now *their* seed phrase, and they must be told so at setup.

### 1.6 Device enrollment / multi-device / rotation

- **Add a device:** re-run §1.3 for a new `device_id`; the same directory identity gets a second enrollment cert. Each device has its own TEE key; compromise of one does not yield the other.
- **Lost/stolen device:** directory revokes that `device_id`'s cert (assertion issuance stops within one TTL); other devices unaffected; volume keys wrapped to the dead device are rotated on next entitlement pass.
- **Device key rotation:** issue a new cert for a fresh TEE key, superseding `not_after`; the old key's assertions expire naturally.

### 1.7 Honest note: this is NOT OIDC/SAML unless bridged

The device-bound ceremony above is a **local** authenticator; it does not speak OIDC or SAML to third-party web apps. Two integration directions:

1. **Federation inbound (spec §3.2):** the org may replace the self-hosted Postern Directory with its **existing IdP via OIDC/SAML** — the IdP answers "is this account active, what groups/attributes," issuing the assertion of Proof 2. *The device-key check (Proof 1) still runs locally.* Honest cost: federating imports the IdP's phishing/failure surface; the device key is what contains the blast radius.
2. **Bridge outbound:** to let corporate web apps consume this identity, Enterprise would run a local **OIDC provider / SAML IdP shim** that mints standard tokens *after* a successful wallet-ceremony login. This is **missing backend** (§3), and it is where classical (non-PQ, phishable) token surface re-enters — any claim of "post-quantum SSO" ends at the bridge boundary and must say so.

For direct WebAuthn relying parties, `crates/postern-keys` already provides an ES256 assertion path — but that is **classical P-256**, not the PQ device key, and most RPs ignore attestation, so the benefit is local/P2P, not "sites trust you more" (stated in the crate's own doc comment).

---

## 2 · Org controls / governance model

### 2.1 Access hierarchy — RBAC + ABAC (both mandatory, default-deny)

- **RBAC** — org tree + roles (`engineer`, `finance-analyst`, `counsel`, `it-admin`, `compliance-officer`). A role bundles entitlements: apps installed, project volumes mountable, network egress classes. **Least-privilege by construction:** `it-admin` conspicuously entitles **no** user-volume access — *admin ≠ access.* (Implemented in Consiglio `ROLES` + `rbacCheck`.)
- **ABAC** — attributes on user (`department`, `clearance`, `project`, `region`, contract type) and resource (sensitivity, COI class, jurisdiction). The gate:
  `mount(volume) ⇐ role ∈ volume.roles ∧ user.clearance ≥ volume.clearance ∧ wall_check(user, volume) = pass`
- **Separation-of-duty** pairs declared in policy (`SOD = [["it-admin","compliance-officer"]]`) and enforced at role assignment — no one holds both audit-custody and IT-admin.

Roles map 1:1 to **per-role machine profiles**: because Postern OS is declarative NixOS, a profile is a Nix expression selected by role at enrollment (app set, mountable volumes, egress classes, hardening baseline), built reproducibly and **attested** (Postern Seal) so both org and employee can verify the fleet runs the genuine profile.

### 2.2 Chinese Wall — Brewer–Nash information barriers

For conflict-of-interest separation (law firms, M&A desks, consultancies) RBAC/ABAC is insufficient — the wall must depend on **history**:

- **Objects** = datasets = per-project encrypted volumes (each has its own key, wrapped to entitled users' device keys).
- Each dataset ∈ a **company dataset group** (e.g. "Client A"); groups ∈ a **COI class** (e.g. "Banking clients" = {Client A, Client B}, competitors).
- **Simple-security rule:** a user may access a dataset in group *g* of COI class *c* **only if they have never accessed a dataset of a different group in the same class *c***. First access is free; it **binds**. (Consiglio `wallCheck`, verbatim: it walks `user.accessed` and denies if any accessed volume shares `classId` but differs in `groupId`.)
- **Mandatory enforcement in the volume-key broker:** a walled user's device is *never given the key* — there is no "open anyway" button; only the audited quorum path can unbind (e.g. after a counsel-set cooling-off period — **LEGAL DETERMINATION REQUIRED (counsel):** durations and wall-crossing standards are bar/professional-conduct decisions).
- **\*-property (write rule) honesty:** full Brewer–Nash write confinement needs OS-level MAC. Postern implements a per-volume **no-cross-copy** policy (clipboard/file-move between different-COI volumes blocked in-session) and **flags** rather than silently permits exports.

> **The wall's hard edge is at-rest only.** Key-withholding is hard denial for data at rest — a walled machine mathematically cannot mount the volume. But once *entitled* data is decrypted in a session, containment is an OS problem requiring **SELinux/AppArmor MAC domains per volume**. On Postern OS that MAC is part of the profile; **anywhere client-side-only — including the Consiglio console, which says so on its face — wall enforcement is advisory.** And no OS stops a human photographing a screen: information barriers are ultimately a *combined* technical + contractual + supervisory control.

### 2.3 Dual-control escrow — no single silent admin

Design goal: **the org can always recover company data/access, and no individual can do it alone or invisibly.**

- At bootstrap the org names a **governance quorum**: N officers (recommend IT admin + compliance/DPO + executive, N ≥ 3), threshold M (recommend M=2 for N=3). Each holds a TEE-sealed keypair. (Consiglio bootstraps a **real 2-of-3**: `makeOfficer` generates an Ed25519/ECDSA sign key + a P-256 ECDH key, each sealed under the officer's own passphrase.)
- Each user's **escrow recovery key** is generated at enrollment and immediately **Shamir-split M-of-N over GF(256)** (Consiglio `shamirSplit` — real Lagrange-interpolation threshold, not theater), each share **ECIES-encrypted to one officer's ECDH public key** (`eciesSeal`: P-256 ECDH + SHA-256 KDF + AES-GCM), so provisioning can distribute shares *without* officer passphrases; only the officer's sealed private key opens a share. The whole key exists only transiently.
- A **release** (recovery / offboarding handover / lawful data-access) requires: a **purpose string recorded verbatim**, **M distinct officer approvals** (each officer unlocks their own key and signs the release record — Consiglio `officerApprove`), and a **chained audit entry written *before* key material is reconstructed**. The employee (or their manager) is **notified by default**; suppressing notification is itself a logged, quorum-approved act. **LEGAL DETERMINATION REQUIRED (DPO/counsel):** lawful delay of notification and lawful access purposes.
- **What escrow cannot do:** read the employee's *personal* space (those keys are never escrowed); or act without a verifiable trail (hash-chained audit replicated to the compliance officer's custody). **Honest limit:** an org colluding at quorum scale *can* read corporate data — that is escrow's **stated purpose** (business continuity, lawful access), not a backdoor; the control is that it cannot happen *silently, singly, or deniably.*

> **GIP-008 tie-in (honest):** the escrow M-of-N is **off-chain Shamir secret sharing over officer keys** — it does *not* use any on-chain threshold signature. The Bloch chain's hybrid ML-DSA-65‖Falcon-1024 signatures have **no practical MPC/threshold construction today** (2027+ research), and the chain is strictly single-signature P2PKH with no script system; on-chain k-of-n multisig needs a consensus change **roadmapped separately as GIP-008** (referenced in `site/build.js`). Enterprise escrow therefore deliberately lives at the *custody/application* layer (Shamir + ECIES to officer keys), independent of and not blocked on GIP-008. If GIP-008 ever lands, on-chain quorum could optionally anchor escrow-release *events*, but it is not required and not assumed.

### 2.4 Revocation & lifecycle

- **Revocation = the assertion stops.** Short-lived assertions mean deprovision takes effect within one TTL even if a revocation push is missed; the push makes it immediate. Every volume-key release re-checks entitlement, bounding offline grace (an org-policy value, **visible to the employee**).
- **Offboarding ceremony (spec §6.2), in order:** (1) revoke — assertion issuance stops, push kills sessions, broker stops honoring wrappings; (2) **freeze, don't peek** — profile/vault stay sealed, termination alone grants no read; (3) escrow-governed handover — M-of-N unwraps the corporate data root, re-seals *scoped* company data to successor/manager; (4) rotate every shared volume key the departed user touched; (5) cryptographic-erase the device profile (destroy TEE keys — instant, verifiable) or remove only the corporate profile on a dual-persona phone; (6) retention handled per counsel's schedule.
- **Succession inherits the role, not the person:** assigning the role re-runs entitlement wrapping *and the wall check* — a successor walled from a COI group does **not** silently inherit its volumes; the conflict surfaces loudly.

### 2.5 Audit — tamper-evident, two-custody

Every sensitive event (provision, role/attr change, wall binding, escrow approval/release, revocation, wipe, policy change) is an entry in a **hash-chained log**: `hash_i = H(canonical(entry_i) ‖ hash_{i-1})`. (Consiglio `auditAppend`/`auditVerify` implement exactly this over `stableStringify` canonicalization + SHA-256, with a `GENESIS` root and a verify-the-chain walk.) Chain heads are periodically **countersigned by the compliance officer's key and replicated outside IT's custody** — tampering requires breaking *both* custodies. Logs record **administrative/security events, not employee content** (minimization applies to the audit trail too); what is recorded about a user is itemized in the transparency panel.

### 2.6 Transparency panel — non-negotiable

Every corporate device shows a permanent, unremovable panel: who manages the device (org + admin-of-record key fingerprints), the governance quorum, the signed policy version (signature failure renders in red), the machine profile, **exactly what telemetry leaves the device** (inventory, posture, policy state, audit events — itemized) and **what does not** (keystrokes, screen/file contents, personal-profile anything, location unless lost-device mode is on — in which case *that* is listed too), the user's wall bindings, and the escrow-notification promise. **There is no covert mode: not disabled — absent. A policy that isn't shown isn't enforced.** (Consiglio's `bootstrapOrg` writes the `monitored`/`notMonitored`/`escrowNotice` lists into the signed policy payload and renders them verbatim.)

### 2.7 Compliance-*enabling* control map (NOT legal advice)

Enterprise provides technical controls that *support* requirement areas; **it certifies nothing.** Summary of the mapping (full table in spec §9):

| Requirement area | Control provided | Counsel owns |
|---|---|---|
| Access & portability (LGPD 18, GDPR 15/20, CCPA) | Per-user encrypted profiles make holdings enumerable; structured machine-readable export | Scope, format, deadline, ID-verification |
| Erasure (LGPD 18 VI, GDPR 17, CCPA) | **Cryptographic erasure** — destroy a key = verifiable immediate deletion; scoped re-keying; audited | Erasure vs legal hold, anonymize vs delete |
| Lawful-basis / purpose limitation (LGPD 6–7, GDPR 5/6/30) | Verbatim purpose string in every policy object + escrow release; enumerated telemetry per policy version | Basis selection, ROPA, DPIA triggers |
| Data minimization | Default telemetry = inventory/posture/policy only; adding an item needs a new *signed, visible* policy version | Proportionality per workforce/jurisdiction |
| Retention | Retention **labels** + crypto-erase jobs; **ships no default period on purpose** | Every period + disposition rule |
| Accountability / audit | Hash-chained dual-custody signed log + attested build | Retention, DPO reporting lines |
| Breach readiness (LGPD 48, GDPR 33–34) | Attestation-failure/wall-violation/anomalous-escrow alerts; forensic timeline; per-volume blast-radius bound; incident export bundle | Whether it's notifiable; timelines; content |
| Cross-border transfers | Region tags pin data/keys to jurisdiction-tagged hosting; egress classes make paths explicit | Transfer mechanism validity (adequacy/SCCs) |
| DPO function | Compliance-officer role gives the DPO real technical teeth (escrow approvals, audit custody, policy countersignature) | Appointing a qualified DPO |

---

## 3 · What's PROTOTYPE vs what backend is MISSING

### 3.1 PROTOTYPE — the Consiglio console (real, working, single-file, strict-CSP)

`apps/postern-enterprise/index.html` genuinely implements, in-browser:

- **Org bootstrap** with a real 2-of-3 governance quorum — each officer a WebCrypto keypair sealed under their own passphrase (`makeOfficer`, `bootstrapOrg`).
- **RBAC role catalog + ABAC** attribute gate + separation-of-duty (`ROLES`, `rbacCheck`, `SOD`).
- **Chinese-Wall editor** — COI classes → dataset groups → volumes, with a simulated file view where first access *binds* and conflicting volumes go key-unavailable (`wallCheck`, `accessVolume`).
- **Provision / offboard ceremonies** with a **genuine Shamir 2-of-3 escrow split/reconstruct over GF(256)** gated on officer passphrases, plus ECIES-to-officer share distribution (`shamirSplit`/`shamirJoin`, `eciesSeal`/`eciesOpen`, `provisionUser`, `officerApprove`).
- **Hash-chained audit log** with a verify-the-chain button (`auditAppend`, `auditVerify`).
- **Employee transparency panel** — the exact screen a managed user sees (`renderTpTab`).
- **Signed, versioned policy** documents (`signObj`/`verifyObj`), the permanent NOT-LEGAL-ADVICE disclaimer, and inline **LEGAL** flags.

**Prototype stand-ins (labeled in the console's own honesty dialog):**

| Real target | Console stand-in | File evidence |
|---|---|---|
| Falcon-1024 ‖ ML-DSA-65 (PQ) | **Ed25519 / ECDSA-P256** WebCrypto | `genSignKeypair`, comment "CLASSICAL STAND-IN" |
| Argon2id | **PBKDF2-SHA-256**, 310k iters | `passKey`, comment "PBKDF2 stand-in for Argon2id" |
| Postern Vault AEAD (XChaCha20) | **AES-256-GCM** | `sealBlob`/`openBlob` |
| Directory + TEE + audit replica | **localStorage** | `persist`, `loadS`/`saveS` |
| OS volume-key broker + MAC | **in-page `wallCheck`** (advisory) | spec §5.2 honest limit |

**The flows are the design of record; the primitives are browser stand-ins.** The console cannot enforce a wall against a determined insider — it demonstrates and audits the model.

### 3.2 MISSING backend — what must be built to make it real

Three services, none of which exist yet:

**(A) Identity service / Postern Directory** — the trust anchor and assertion issuer.
- Holds the directory signing key (chained to the offline org root); issues enrollment certificates and short-lived login assertions.
- Verifies device **attestation evidence** at enrollment (`postern-core::seal::attestation_transcript` already defines the signed bytes; the *verifier* is `postern-seal-companion`, but the directory-side attestation-verification service and enrollment-cert issuance are not built).
- Revocation push + short-TTL assertion refresh.
- **Federation bridge (OIDC/SAML):** both directions — inbound (delegate assertion issuance to the org IdP) and outbound (a local OIDC provider / SAML IdP shim that mints standard tokens after a wallet-ceremony login). **This is the OIDC/SAML story and it does not exist.** It is also where PQ guarantees end.
- Real **PQ device keys**: swap the console's Ed25519 stand-in for `bloch_mobile::WalletCore`'s hybrid sign path (already exists in `postern-sdk`), with TEE sealing (StrongBox/Secure Enclave — planned app-layer work per `postern-vault` doc, not shipped).

**(B) Policy engine + volume-key broker** — the enforcement core.
- The RBAC/ABAC/Brewer–Nash checks currently run *in-page* (`rbacCheck`, `wallCheck`). Real enforcement must live in an **OS-side volume-key broker** that wraps/releases per-volume keys to device keys and **withholds the key** on a wall failure — hard at-rest denial.
- **OS-level MAC** (SELinux/AppArmor domains per volume) for in-session write confinement — the \*-property. This is a NixOS profile concern (`os/desktop.nix`, `os/mobile.nix`); the per-volume MAC domains are not yet implemented.
- Signed policy distribution + machine-profile (Nix expression) selection by role at enrollment.

**(C) Audit log service** — tamper-evident, two-custody, persistent.
- The chain construction is real (`auditAppend`) but persists to localStorage. Production needs a **replicated, dual-custody append-only store** with the compliance-officer countersignature on chain heads, held outside IT's custody, plus the chain-walk verification API and the incident-export bundler.

**Cross-cutting missing pieces:** the offline-grace enforcement loop (re-check entitlement on every volume mount); cryptographic-erase orchestration for offboarding; key-rotation orchestration; the region-pinning of key material to jurisdiction-tagged hosting; and an external **security audit** of the whole thing.

---

## 4 · Minimal buildable MVP

The smallest thing that turns "labeled prototype" into "real, if unaudited, wallet-as-login with governance" — build in this order:

1. **Real PQ device-key enrollment + login (replace the Ed25519 stand-in).** Wire `bloch_mobile::WalletCore` (`postern-sdk`) hybrid sign/verify into the enrollment (§1.3) and login (§1.4) ceremonies on one platform (Android StrongBox first, per `POSTERN-IDENTITY`). Deliverable: a device proves identity by signing a `postern:login:v1` challenge hybrid, verified against an enrollment cert. *No OIDC yet — local ceremony only, honestly labeled "not SSO to web apps yet."*
2. **Minimal Directory service (identity backend).** A small self-hosted service that: issues single-use enrollment tokens, verifies the attestation transcript (`postern-core::seal` + `postern-seal-companion`), issues signed enrollment certs, and mints short-TTL login assertions with a revocation list. Persist to a real store, not localStorage. This is the one indispensable backend.
3. **Volume-key broker with hard wall enforcement.** Port `wallCheck` + `rbacCheck` server-/OS-side so the broker **withholds** per-volume keys on failure (hard at-rest denial). Ship *without* in-session MAC first, with the advisory-limit disclosure carried forward verbatim.
4. **Persistent dual-custody audit log.** Lift `auditAppend`/`auditVerify` to a replicated append-only store with compliance-officer countersignature on chain heads. Keep the Shamir + ECIES escrow exactly as the console already does it (it is already real crypto) — just persist shares to officer-held stores.

**Explicitly deferred (post-MVP):** OIDC/SAML bridge (both directions), OS-level MAC / \*-property, HSM-backed org root, region-pinned hosting, cryptographic-erase orchestration, and the external security audit — none are needed to demonstrate a working, honest wallet-as-login + governance loop, and all are called out as gaps rather than quietly assumed.

---

> **Closing disclaimer (same as the opening):** engineering, not law; unaudited; wallet-as-login is novel and untested at scale. Postern Labs does not certify compliance with LGPD, GDPR, CCPA/CPRA or any regime. Every **LEGAL DETERMINATION REQUIRED (DPO/counsel)** marker is a decision this architecture is *waiting for* from qualified professionals before an org relying on it can claim anything about compliance.
