# Postern Identity — Sign-In With Postern Wallet (design spec)

**Product (Postern Labs). Status: design + reference flow.** The Postern
platform login is **not an email account** (unlike Windows/Android/iCloud).
It is the user's **own Postern wallet**, configured once at setup and unlocked
with a user-created passphrase. Logging in = **unlocking your wallet locally
and signing a fresh challenge with it.** No email, no account server, no
password database, no third-party identity provider.

> This is the passkey / "Sign-In-With" pattern — **but post-quantum and
> self-custodied.** A classical passkey is an ECDSA/EdDSA keypair held by a
> platform vendor's sync fabric; the Postern identity is a **hybrid
> Falcon-1024 ‖ ML-DSA-65 keypair** derived from a BIP39 seed the user alone
> holds, sealed in the device TEE.
>
> Reference flow: `apps/postern-login/index.html` (codename **Chiave**) — a
> fully local, single-file demonstration of the whole ceremony, with the
> browser-imposed stand-ins labeled. Grounding: the wallet/crypto primitives
> below are the **existing** `bloch-crypto` API (`wallet`, `crypto`,
> `hd_wallet`), plus `postern-vault` and `postern-panic`.

## The model — identity is the wallet

- **Root of identity: the BIP39 seed.** At setup the user generates (or
  restores) a 24-word mnemonic (`bloch_crypto::SeedPhrase` — BIP39 English
  wordlist, checksum, PBKDF2-2048 → 64-byte seed; ~256 bits entropy). The
  mnemonic is shown **once**, with the blunt warning that it is the only
  recovery.
- **The keys: hybrid Falcon-1024 ‖ ML-DSA-65** (`bloch_crypto::crypto` +
  `crypto::falcon`) — two distinct lattice families (NTRU vs Module-LWE/SIS),
  both must verify, so a break of one assumption does not forge a login.
  ML-DSA-65: pk 1952 B, sig 3309 B. Falcon-1024 adds the second signature.
- **At rest, the wallet secret is sealed** — exactly the existing
  `bloch-crypto` keyfile construction: **AES-256-GCM** under a key from
  **Argon2id** (m = 64 MiB, t = 3, p = 1 — the shipped `postern-core` at-rest
  parameters) over
  the user's passphrase, or wrapped by a **non-exportable TEE key**
  (StrongBox / Secure Enclave, per `POSTERN-CONTAINER.md`). Only ciphertext
  ever touches disk.
- **Login is a local ceremony** — no server is consulted:

  1. The lock screen prompts for the passphrase (or a biometric — see below).
  2. Passphrase → Argon2id → key → AES-256-GCM decrypt of the sealed wallet
     secret (all-or-nothing: a wrong passphrase fails the GCM tag; there is
     no partial unlock and no oracle beyond "wrong passphrase").
  3. The **m/login identity key** is derived (never the spending key — see
     key separation).
  4. The login manager issues a **fresh random challenge**
     `{v:"postern:login:v1", nonce(32 B), device_id, ts}` and the wallet
     signs it hybrid (Falcon ‖ ML-DSA). The manager verifies **both**
     signatures against the enrolled login public key.
  5. On success the session opens: the profile's FBE keys and the **vault
     key** are released, so the apps' sealed secrets become available.

- **What holds the "account"?** Nothing but the device. The only enrolled
  state is the login *public* key (public by definition) plus the sealed
  ciphertext. There is no password database to breach — anywhere.

## Key separation — m/login vs m/spend (defense in depth)

No BIP32-style hardened derivation standard exists for lattice keys yet (the
`hd_wallet` module states this honestly). `bloch-crypto` instead derives
independent keys by **domain-separated deterministic sub-seeds** — the same
construction its diversified addresses already use
(`diversified_seed` = SHA3-256 over a domain tag ‖ master seed ‖ index).
Postern Identity specifies these paths:

| Path (semantic)   | Concrete derivation                                                          | Key                    | Purpose |
|-------------------|------------------------------------------------------------------------------|------------------------|---------|
| `m/spend/i`       | SHA3-256(`"bloch:diversifier:v1"` ‖ seed ‖ le32(i)) → `generate_keypair_from_seed` | ML-DSA-65 (+ Falcon)   | Funds. The existing diversified-address family — unchanged. |
| `m/login/d`       | SHA3-256(`"postern:login:v1"` ‖ seed ‖ le32(d)) → `generate_keypair_from_seed`     | ML-DSA-65 **anchor**   | OS login + identity anchor; `d` = device index. |
| `m/login/d` (Falcon half) | `falcon::keypair()` at enrollment, **certified by the anchor**, sealed in the TEE keystore | Falcon-1024 | The hybrid second signature (see note below). |
| `m/app/<name>`    | SHA3-256(`"postern:app:<name>:v1"` ‖ seed) → `generate_keypair_from_seed`          | ML-DSA-65              | Per-app peer identity (Sotto, Vedetta, Courier, Messenger), certified by the login anchor; unlinkable across apps. |
| vault root        | SHA3-256(`"postern:vault:v1"` ‖ seed) → 32-byte KEK                                | symmetric              | Wraps the `postern-vault` key. |

Why this split matters:

- **Authenticating never exposes the funds key.** The login path is exercised
  many times a day, on the platform's most attacked surface (the lock
  screen). The `m/spend` sub-seed is *never derived* during authentication —
  spending requires its own explicit unlock. A compromise of the login flow
  (evil lock screen, coerced signature) yields signatures under `m/login`,
  which moves no funds.
- **Independence is cryptographic, not procedural.** The domain tags are
  distinct SHA3-256 inputs; the sub-seeds are computationally independent
  32-byte seeds; `generate_keypair_from_seed` is deterministic per seed
  (Sprint T.1). Learning one derived key reveals nothing about a sibling.
- **Falcon-half honesty.** `bloch-crypto` derives ML-DSA-65 deterministically
  from a seed, but Falcon keygen is currently random (floating-point Gaussian
  sampling; see the B6 notes). So the **seed-derived ML-DSA anchor is the
  durable identity** — always recoverable from the mnemonic alone — and the
  Falcon half is device-resident, sealed in the keystore, and re-enrolled on
  restore by having the anchor cross-sign the fresh hybrid public key. This
  mirrors `hd_wallet`'s documented backup model and will collapse into full
  seed derivation when a lattice HD standard lands.

## Biometric unlock — a convenience gate, not a root of trust

Biometrics (fingerprint / face) may unlock the wallet **for convenience**, but
they are a *gate in front of the TEE-held key*, never a replacement for the
passphrase and never a new root of trust:

- **On device:** the wallet-wrapping key is sealed in hardware — Android
  **StrongBox** with `setUserAuthenticationRequired` + **BiometricPrompt**;
  iOS **Secure Enclave** via LocalAuthentication with
  `kSecAccessControlBiometryCurrentSet`. The TEE releases/uses the key only
  after a successful biometric check. The biometric never *is* the key; it
  only authorizes the hardware to use it.
- **Enrollment-change hardening:** the sealed key is **invalidated when the
  biometric set changes** (`kSecAccessControlBiometryCurrentSet` /
  `setInvalidatedByBiometricEnrollment(true)`) — an attacker who adds their
  own fingerprint gains nothing; the wallet falls back to passphrase.
- **The passphrase always remains.** Enrolling a biometric does not delete or
  weaken the passphrase path; it must always exist as fallback (biometric
  hardware fails, lockouts happen).
- **Biometrics are not recovery.** A biometric cannot recover a lost seed or
  a forgotten passphrase — it only gates a key that already exists on this
  device. The seed remains the only recovery (below).
- **Coercion caveat — Panic Lock disables biometric unlock.** A fingerprint
  can be taken by force; a passphrase at least requires the victim to speak.
  Triggering **Panic Lock** (`postern-panic`) therefore *disables the
  biometric path entirely* — the wallet becomes passphrase-only until the
  owner deliberately re-enables it. (This composes with the lockout/eviction
  policies in `POSTERN-DEADBOLT.md`.)
- **In the web reference flow:** the browser stand-in is the **WebAuthn
  platform authenticator** (`navigator.credentials.create/get`,
  `authenticatorAttachment:"platform"`, `userVerification:"required"` — Touch
  ID / Windows Hello / Android biometric) with the **PRF extension** so the
  biometric assertion actually releases key material that decrypts the sealed
  wallet copy — a real cryptographic gate, not theater. Labeled as a stand-in
  for the TEE's biometric-gated key release. If the platform authenticator or
  PRF is unavailable, the option is hidden and the passphrase path stands.

## Unified identity — one sovereign key for everything

The same wallet identity is, simultaneously:

- **The OS login** (this spec) — desktop lock screen / mobile container
  challenge.
- **The app and peer identity** — Sotto, Vedetta, Courier, Messenger derive
  their peer keys on `m/app/<name>`, certified by the login anchor. Adding an
  app never creates an account; it derives a key.
- **The wallet** — `m/spend` is the same seed's funds family
  (`bloch-crypto`'s diversified addresses).
- **The attestation anchor** — the login anchor certifies the device's TEE
  keys, and Key Attestation / Postern Seal (`POSTERN-CONTAINER.md`) binds
  them to genuine hardware and verified boot state.
- **The vault root** — the `postern-vault` key (XChaCha20-Poly1305 vault
  engine) is wrapped under the vault KEK on the table above. **Unlocking at
  login unlocks the app secrets**: e.g. Sotto's Anthropic API key lives
  sealed in the Vault and simply becomes available when the user signs in —
  no second password, no plaintext key in localStorage.
- **Panic Lock composes** (`postern-panic::PanicSession`): one gesture seals
  the vault back to ciphertext and evicts the keys from RAM. Nothing is
  destroyed; the owner re-authenticates (passphrase — *not* biometric, see
  above) to reopen.

## Honest tradeoffs — read this before shipping anything

- **The seed phrase is the ONLY recovery. Full stop.** There is no email
  reset, no security questions, and no support desk that can recover a
  Postern identity — by construction, since no party but the user ever holds
  the secret. A **forgotten passphrase** is recoverable: restore from the
  seed and set a new passphrase. A **lost seed** (with a forgotten passphrase
  or lost device) is **permanent, unrecoverable loss** of the identity and
  the funds — the same deal as any self-custodied wallet. The product must
  say this in plain words at setup, and the reference flow does.
- **This trades a remote risk for a local one.** Email login can be phished,
  breached, and subpoenaed at the provider — but it survives a house fire.
  A seed on paper survives no fires and no burglars. Postern's position:
  the local risk is the user's to manage (steel backup plates, distributed
  copies); the remote risk was never manageable by the user at all.
- **Single-key concentration.** One root secret now guards login, apps,
  funds, and attestation. Mitigations, in depth: (1) the **TEE holds the
  working keys non-exportably** — compromise requires the physical device
  *plus* passing user authentication, not a copied file; (2) **unlock is
  local-only** — there is no remote endpoint to credential-stuff, and a wrong
  passphrase yields nothing but a failed GCM tag; (3) the **m/login / m/spend
  split** means the daily-exercised surface cannot move funds; (4) per-app
  subkeys compartmentalize peer identities; (5) the seed itself is needed
  only at setup/restore and should never exist on a running system
  afterwards. Residual truth: whoever holds seed + passphrase *is* the user.
  That is the self-custody bargain, stated, not hidden.
- **Coercion of a passphrase is out of scope here** — it is covered by
  **Panic Lock** (`postern-panic`, `POSTERN-DEADBOLT.md`): instant re-lock to
  at-rest ciphertext, nothing destroyed, biometric path disabled. Postern
  Identity deliberately does not attempt its own duress logic.
- **Availability honesty:** lose the device without a seed backup and you are
  locked out of everything at once — email-based platforms degrade more
  gracefully. This is the cost of the model and users must be told.

## Compared to email login and classical passkeys

| Attack / property            | Email + password                | Classical passkey (WebAuthn)      | **Postern Identity** |
|------------------------------|---------------------------------|-----------------------------------|----------------------|
| Server password-DB breach    | The canonical breach            | N/A                               | **N/A — no server, no DB** |
| Phishing / fake login page   | Works                           | Origin-bound, resists             | **No remote login exists to fake** |
| Email-takeover → reset flow  | Account lost                    | Recovery email often still root   | **No reset flow exists** |
| IdP outage / account ban     | Locked out by a third party     | Vendor sync fabric can lock out   | **No third party** |
| Quantum adversary            | Irrelevant (server-side hash)   | ECDSA/EdDSA — Shor-breakable      | **Falcon-1024 ‖ ML-DSA-65 (FIPS 204)** |
| Custody of the credential    | Provider                        | Platform vendor (cloud-synced)    | **The user, alone** |
| Recovery when all is lost    | Email reset (their mercy)       | Vendor account recovery           | **Seed phrase or nothing — stated plainly** |

Attack surface removed: the password database, the phishing target, the reset
flow, the recovery email, the IdP. Attack surface accepted: the seed backup
and the device — surfaces the user can actually see and defend.

## Reference flow — `apps/postern-login/index.html`

A single self-contained file, in the Postern instrument-panel identity (its
own iris accent; Sotto wears brass, Vedetta steel blue), light + dark,
accessible, **fully local — zero network destinations of any kind**. It
demonstrates the real ceremony end to end: seed shown once → passphrase-sealed
at rest (AES-256-GCM, PBKDF2-derived key, ciphertext-only in localStorage) →
local unlock → derive the login key → sign a fresh challenge → verified
session → vault-sealed app secret unlocked by login → lock / Panic Lock /
erase. Browser-imposed stand-ins, labeled in-app exactly as Sotto/Vedetta
label theirs:

| In the demo                                   | In the product |
|-----------------------------------------------|----------------|
| Ed25519 (or ECDSA P-256) via WebCrypto        | Hybrid Falcon-1024 ‖ ML-DSA-65 in the TEE |
| PBKDF2-SHA-256, 310,000 iterations            | Argon2id (64 MiB, t = 3) — memory-hard |
| SHA-256 domain tags                           | SHA3-256 domain tags (as in `bloch-crypto`) |
| 256-word demo wordlist, 24 words + checksum   | BIP39 English 2048-word list, 24 words |
| WebAuthn platform authenticator + PRF         | StrongBox / Secure Enclave biometric-gated key release |
| Stand-in keypair generated at setup, sealed with the seed | ML-DSA anchor derived deterministically from the seed (stable fingerprint across restores); Falcon half re-enrolled |

The flow is the real design; only the primitives are stand-ins.

## Scope / build path

1. Nothing new cryptographically: reuse `bloch-crypto` keyfile sealing
   (Argon2id + AES-256-GCM), `generate_keypair_from_seed`, the
   domain-separated derivation pattern, `postern-vault`, `postern-panic`.
2. Desktop: a PAM module / greeter that runs the challenge ceremony against
   the sealed keyfile; session start releases the vault KEK.
3. Mobile (container): the managed-profile challenge is the wallet unlock;
   StrongBox key + BiometricPrompt gate; Key Attestation binds the anchor.
4. App SDK: `m/app/<name>` derivation + "seal under the platform vault"
   API so apps stop storing their own secrets (Sotto's API key first).
5. The setup/restore UX with the recovery warning verbatim from this spec.
