// SPDX-License-Identifier: MIT OR Apache-2.0
//! Android **Key Attestation** verification — the `mobile` attestation backend
//! the Postern Container's `StrongBoxKey.kt` cites but that did NOT exist in
//! this verifier until now (the tree shipped only the SEV-SNP / TDX / pinned
//! device-key backends). This module parses an Android Key-Attestation X.509
//! certificate chain, verifies it up to a **caller-pinned Google attestation
//! root**, and checks the fields that make the claim meaningful: the verifier
//! **nonce** (attestation challenge), **verified-boot state + device-locked**,
//! **OS patch level** (anti-rollback), the **attesting app identity**
//! (`AttestationApplicationId`), and the **security level** (StrongBox vs TEE).
//! It returns the crate-shared [`crate::Verdict`], fail-closed on any doubt.
//!
//! ## What a [`Verdict::Genuine`] here proves — and what it does NOT
//!
//! On [`Verdict::Genuine`] this proves: *a hardware key on a device whose
//! verified-boot state, OS patch level and attesting-app identity are AS
//! REPORTED, attested by a chain that terminates at the Google attestation
//! root the caller pinned, freshly bound to the caller's nonce.*
//!
//! It does **NOT** prove anything about the **workspace**. Android Key
//! Attestation measures the **phone** and *identifies* the app — it does not
//! measure the container's code or contents. This is **key-attested device,
//! not measured-boot workspace** (that property is exclusive to Postern OS
//! Mobile). And the whole chain roots in **Google's** CA + the OEM: a real,
//! for an ownerless-protocol ethos ironic, third-party trust dependency.
//! StrongBox itself is a **classical P-256** HSM — it attests the device and
//! wraps the post-quantum key at rest; it does **not** hold or sign with the
//! Falcon‖ML-DSA key in hardware.
//!
//! ## Fail-closed, like the rest of the crate
//!
//! - **No pinned roots ⇒ [`Verdict::Unverified`].** With nothing to anchor the
//!   chain to, the chain authenticates nothing — mirroring how
//!   [`crate::verify_report`] refuses a report with no `trusted_pubkey`.
//! - Any parse error, broken chain link, failed signature, expired cert, or
//!   field mismatch is a **named** [`Verdict::Mismatch`] — no partial trust.
//!
//! ## Trust-root rotation & revocation (the honest operational limit)
//!
//! Google rotated the RKP attestation root (2026-02-01, mandatory 2026-04-10),
//! so the pinned root is a **moving target**: [`MobileExpected::roots`] is
//! caller-supplied *by design* so the deployment can track the current
//! root(s) out of band and pin more than one across a rotation window. This
//! is deliberately UNLIKE `crate::tdx`'s `PINNED_INTEL_SGX_ROOT_CA_DER`
//! (Intel's SGX root is long-lived and rarely rotates, so compiling it in is
//! safe) — hardcoding a Google root DER here would silently go stale on
//! rotation. See [`GoogleRootPinProvenance`] for the exact fetch procedure
//! and the one open config item this leaves for an operator.
//!
//! Status-list revocation is a **caller-supplied [`MobileRevocationPolicy`]**,
//! mirroring the SEV-SNP verifier's `RevocationPolicy` (`snp.rs`, feature
//! `sev-snp`) safe-by-default shape: a caller MUST name a policy — either
//! [`MobileRevocationPolicy::Enforce`] against a caller-fetched
//! [`GoogleStatusList`], or the loudly-named
//! [`MobileRevocationPolicy::SkipRevocationCheckDangerously`] opt-out — so a
//! caller who "does nothing special" can never silently skip revocation.
//! Consistent with the snp/tdx CRL discipline, **this crate still does NO
//! network I/O and carries NO JSON dependency**: the operator fetches
//! `GET https://android.googleapis.com/attestation/status` out of band (see
//! [`GoogleRootPinProvenance`] step 5), parses the JSON serial→status map,
//! and hands the crate the set of revoked serials plus the fetch metadata; the
//! verifier only reads them.
//!
//! ### In-crate freshness gate (closes the staleness residual)
//!
//! Google serves the status list with an HTTP `Cache-Control` max-age but the
//! JSON body carries no signed `nextUpdate` the way an X.509 CRL does, so a
//! stale cached copy could mask a *fresh* revocation. To keep the same
//! discipline as `snp`'s CRL `nextUpdate` check, [`GoogleStatusList`] carries
//! an operator-supplied **`fetched_at_unix` + `max_age_secs`**, and
//! [`GoogleStatusList::check_freshness`] fails **closed** with
//! [`Verdict::Unverified`] once `now_unix` is past `fetched_at + max_age`
//! (or before the fetch instant — negative age is bogus clock skew). The
//! operator supplies the staleness bound because, unlike an X.509 CRL, the
//! JSON blob is not self-dating; the *comparison* is nonetheless enforced
//! in-crate, so an enforcing caller cannot accept an aged-out list.
//!
//! Honest residual: the JSON schema parse itself stays operator-side (the
//! crate takes pre-parsed serials, keeping its no-I/O / no-JSON-dep shape),
//! and — like the rest of this module — the path is vector-tested, never run
//! against a real StrongBox chain. Same honesty standard as `tdx.rs`'s stated
//! PCK-chain-expiry gap.
//!
//! ## Assurance
//!
//! **Reference-prototype / UNAUDITED.** The ASN.1 KeyDescription parser and
//! the field checks are unit-tested against hand-built DER vectors; the chain
//! signature path uses `x509-parser`'s ring-backed verifier. It has **never
//! been run against a cert chain produced by a real StrongBox on hardware**
//! (`vector-tested ≠ attested`). No security claim until an audit gate.

use x509_parser::asn1_rs::{Any, Class, FromDer, Tag};
use x509_parser::certificate::X509Certificate;
use x509_parser::time::ASN1Time;

use crate::Verdict;

/// DER OID *content* bytes of `1.3.6.1.4.1.11129.2.1.17` — the Android
/// Key-Attestation certificate extension carried in the leaf cert. Compared
/// against `X509Extension::oid.as_bytes()` so we need no OID-macro dependency.
const KEY_ATTESTATION_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x01, 0x11];

/// Sanity ceiling on a caller-supplied chain's length (see
/// `verify_key_attestation_detailed`'s chain-length guard). Real Android
/// Key-Attestation chains are 3-4 certs; this is a generous DoS/sanity bound,
/// not a realistic chain shape.
const MAX_CHAIN_LEN: usize = 8;

// Context-specific tag numbers inside an `AuthorizationList` (KeyMint/Keymaster).
const TAG_ROOT_OF_TRUST: u32 = 704;
const TAG_OS_PATCH_LEVEL: u32 = 706;
const TAG_ATTESTATION_APPLICATION_ID: u32 = 709;

/// Attestation `SecurityLevel` (KeyMint `ENUMERATED`), ordered weakest→strongest
/// so a deployment can require a floor. `Software < TrustedEnvironment < StrongBox`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// Attested in software only — the key is NOT hardware-backed.
    Software,
    /// Trusted Execution Environment (a TEE keymaster/KeyMint).
    TrustedEnvironment,
    /// Discrete StrongBox HSM — side-channel-resistant hardware.
    StrongBox,
}

impl SecurityLevel {
    fn from_enum(v: u64) -> Option<Self> {
        match v {
            0 => Some(SecurityLevel::Software),
            1 => Some(SecurityLevel::TrustedEnvironment),
            2 => Some(SecurityLevel::StrongBox),
            _ => None,
        }
    }
}

/// Android verified-boot state (`RootOfTrust.verifiedBootState` `ENUMERATED`).
/// Only [`VerifiedBootState::Verified`] means a locked, OEM-signed boot chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedBootState {
    /// Full chain of trust to the OEM root — a locked, certified device.
    Verified,
    /// User-installed root of trust (unlocked bootloader, custom key).
    SelfSigned,
    /// Bootloader unlocked, no verification.
    Unverified,
    /// Verification explicitly failed.
    Failed,
}

impl VerifiedBootState {
    fn from_enum(v: u64) -> Option<Self> {
        match v {
            0 => Some(VerifiedBootState::Verified),
            1 => Some(VerifiedBootState::SelfSigned),
            2 => Some(VerifiedBootState::Unverified),
            3 => Some(VerifiedBootState::Failed),
            _ => None,
        }
    }
}

/// The attesting-app identity a verifier requires — extracted from the
/// software-enforced `AttestationApplicationId`. A check passes only if EVERY
/// expected package name AND EVERY expected signing-cert digest is present in
/// what the attestation reports (so a foreign app cannot masquerade as ours).
#[derive(Debug, Clone, Default)]
pub struct AppIdentity {
    /// Required package name(s), e.g. `labs.postern.wallet`.
    pub package_names: Vec<String>,
    /// Required app signing-certificate SHA-256 digest(s) (raw bytes).
    pub signature_digests: Vec<Vec<u8>>,
}

/// The config item [`MobileExpected::roots`] needs an operator to supply: WHERE
/// and HOW to fetch Google's **current** Android Key-Attestation root
/// certificate(s), and how to record what was fetched for audit/rotation
/// tracking. This is a **documentation aid**, not a network client — the
/// crate does no I/O (workspace discipline: verifier logic only, evidence fed
/// in by the caller). It exists so a deployment has one canonical place
/// recording provenance for its pinned roots, and so this fetch procedure is
/// written down exactly once instead of tribal knowledge.
///
/// ## Why this is operator-updatable, not a compiled-in constant
///
/// Contrast with `crate::tdx`'s `PINNED_INTEL_SGX_ROOT_CA_DER`: Intel's SGX
/// root is a long-lived CA that rotates rarely, so compiling its DER into the
/// crate is safe. Google's Android hardware-attestation root is a MOVING
/// TARGET by comparison — it rotated 2026-02-01 (old root mandatory-retired
/// 2026-04-10) and can rotate again without this crate's knowledge. Hardcoding
/// a DER here would either silently reject genuine devices once Google
/// rotates past a stale compiled-in pin, or (worse) tempt a maintainer to defer
/// updating it indefinitely. [`MobileExpected::roots`] stays caller-supplied by
/// design; this type documents the fetch procedure without embedding bytes
/// that would only be correct until the next rotation.
///
/// ## Fetch procedure (operator, before every hardware day / rotation window)
///
/// 1. Fetch the current root set: `GET https://android.googleapis.com/attestation/root`
///    — Google's own docs describe this as "a JSON-formatted array" of
///    base64-encoded X.509 DER root certificates (confirmed against Google's
///    published Android Key Attestation developer documentation).
/// 2. Respect the response's `Cache-Control` header for how long to trust the
///    fetched set before re-checking — Google's own stated guidance, so a
///    network round-trip is not required for every verification.
/// 3. Independently verify at least one fingerprint out of band (e.g. against
///    a second, offline-recorded copy from a prior fetch, or a SHA-256
///    announced through a channel Google does not solely control) before
///    trusting a freshly-fetched root — this crate does no network I/O and
///    cannot perform this step for the caller; see [`root_fingerprint_sha256`].
/// 4. Pin ALL currently-valid roots from the fetched array into
///    [`MobileExpected::roots`] — the array legitimately contains more than
///    one root during a rotation window, and pinning only one risks rejecting
///    a genuine device still presenting the other.
/// 5. Also fetch the revocation status list —
///    `GET https://android.googleapis.com/attestation/status` — see the
///    module-level "Trust-root rotation & revocation" section: parse the JSON
///    serial→status map into a [`GoogleStatusList`] and hand it to
///    [`MobileRevocationPolicy::Enforce`], which this crate now consumes via
///    [`verify_key_attestation_with_revocation`] — the freshness gate and the
///    revoked-serial check both run in-crate, still with NO verify-time network.
#[derive(Debug, Clone)]
pub struct GoogleRootPinProvenance {
    /// Unix seconds when `roots` was last fetched from Google (step 1 above).
    pub fetched_at_unix: i64,
    /// The URL fetched — an audit trail field, not re-fetched by this crate.
    pub source_url: &'static str,
    /// SHA-256 fingerprint(s) of each pinned root DER, recorded at fetch time
    /// for the out-of-band cross-check in step 3 above (see
    /// [`root_fingerprint_sha256`]).
    pub sha256_fingerprints: Vec<[u8; 32]>,
}

impl GoogleRootPinProvenance {
    /// The canonical source URL an operator fetches the CURRENT root set from
    /// (fetch procedure step 1). Documentation constant, not a live client —
    /// this crate does no network I/O.
    pub const ROOT_LIST_URL: &'static str = "https://android.googleapis.com/attestation/root";
    /// The canonical source URL for the revocation/status list (fetch
    /// procedure step 5) — consumed by this crate via
    /// [`MobileRevocationPolicy::Enforce`] over a caller-parsed
    /// [`GoogleStatusList`]; see the module-level "Trust-root rotation &
    /// revocation" section.
    pub const STATUS_LIST_URL: &'static str = "https://android.googleapis.com/attestation/status";
}

/// SHA-256 fingerprint of a root certificate's raw DER bytes — the primitive
/// [`GoogleRootPinProvenance`]'s fetch procedure step 3 needs for an operator
/// to record and cross-check a freshly-fetched root out of band, mirroring how
/// `tdx.rs`'s module docs assert Intel's root fingerprint as a sanity check.
pub fn root_fingerprint_sha256(root_der: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(root_der);
    let out = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

/// Expected values + trust anchors for a genuine Postern Container attestation.
/// The Android analogue of [`crate::Expected`], anchored by pinned Google roots
/// instead of a single out-of-band device key.
#[derive(Debug, Clone)]
pub struct MobileExpected {
    /// Pinned Google attestation root certificate(s), DER-encoded, supplied
    /// out of band. The chain's terminal cert must equal one of these OR be
    /// signed by one of them. **Empty ⇒ [`Verdict::Unverified`]** (fail closed):
    /// with no anchor the chain proves nothing. Pin MORE than one across an RKP
    /// rotation window (see module docs and [`GoogleRootPinProvenance`] for the
    /// exact fetch procedure — this is the RUNBOOK's one open config item for
    /// the mobile platform; it is deliberately operator-updatable, NOT a
    /// compiled-in constant).
    pub roots: Vec<Vec<u8>>,
    /// The single-use nonce the verifier issued; must equal the leaf's
    /// `attestationChallenge`. Freshness/anti-replay.
    pub challenge: Vec<u8>,
    /// Require `deviceLocked == true` in the hardware-enforced RootOfTrust.
    pub require_device_locked: bool,
    /// Require `verifiedBootState == Verified`. Keep `true` for a hardened
    /// deployment; a custom-ROM-friendly deployment may relax it, but must then
    /// NOT claim a locked boot chain.
    pub require_verified_boot: bool,
    /// Minimum attestation `SecurityLevel` the key must meet (e.g. require
    /// [`SecurityLevel::StrongBox`], or accept [`SecurityLevel::TrustedEnvironment`]
    /// for the TEE-fallback tier). Reported back on success for tier UI.
    pub min_security_level: SecurityLevel,
    /// Minimum acceptable OS patch level as `YYYYMM` (anti-rollback). `None`
    /// waives the check (document per deployment).
    pub min_os_patch_level: Option<u32>,
    /// Required attesting-app identity, or `None` to skip (weaker — a verifier
    /// that does not pin the app accepts an attestation minted by any app).
    pub expected_app: Option<AppIdentity>,
    /// Wall-clock (unix seconds) to check each chain cert's validity window
    /// against. `None` skips the time check (document per deployment).
    pub now_unix: Option<i64>,
}

/// The authenticated facts extracted from a [`Verdict::Genuine`] attestation —
/// returned by [`verify_key_attestation_detailed`] for tier/UI reporting.
#[derive(Debug, Clone)]
pub struct MobileAttestation {
    /// The security level the key was actually attested at (StrongBox vs TEE) —
    /// drives the honest "tier it actually got" UI.
    pub security_level: SecurityLevel,
    /// Hardware-enforced device-locked state.
    pub device_locked: bool,
    /// Hardware-enforced verified-boot state.
    pub verified_boot_state: VerifiedBootState,
    /// OS patch level (`YYYYMM`) if reported.
    pub os_patch_level: Option<u32>,
    /// Attesting-app package name(s) as reported.
    pub package_names: Vec<String>,
    /// Attesting-app signing-cert digest(s) as reported.
    pub signature_digests: Vec<Vec<u8>>,
}

// ── status-list revocation + freshness gate ────────────────────────────────

/// A caller-fetched copy of Google's Android Key-Attestation **status list**
/// (`GET https://android.googleapis.com/attestation/status`), reduced to what
/// this verifier needs: the set of **revoked serial numbers** plus the
/// operator-supplied **freshness metadata** that lets an in-crate staleness
/// gate run.
///
/// The crate does **no** network I/O and carries **no** JSON dependency
/// (workspace discipline: verifier logic only, evidence fed in by the caller),
/// so the operator fetches the JSON out of band, parses the serial→status map,
/// and hands over `revoked_serials` already extracted. What this type adds over
/// a bare `Vec` of serials is the **freshness clock**: because Google's JSON
/// body carries no signed `nextUpdate` (unlike an X.509 CRL), the operator must
/// record *when* they fetched it (`fetched_at_unix`) and *how long* they will
/// trust that snapshot (`max_age_secs`). [`GoogleStatusList::check_freshness`]
/// then enforces the bound in-crate, mirroring `snp`'s CRL `nextUpdate` check.
#[derive(Debug, Clone)]
pub struct GoogleStatusList {
    /// Certificate serial numbers Google lists with a non-valid status
    /// (`REVOKED` / `SUSPENDED`), each as **raw serial bytes** — compared
    /// against a chain cert's `raw_serial()`. Operator-extracted from the JSON
    /// serial→status map; presence here (any non-valid status) is a revocation.
    pub revoked_serials: Vec<Vec<u8>>,
    /// Unix seconds when the operator fetched this list from Google. The start
    /// of the freshness window; a `now_unix` *before* this is bogus clock skew.
    pub fetched_at_unix: i64,
    /// How long (seconds) the operator will trust this fetched snapshot before
    /// it must be refreshed — the staleness bound. The analogue of an X.509
    /// CRL's `nextUpdate` interval, supplied out of band because Google's JSON
    /// body is not self-dating (its freshness lives in the HTTP `Cache-Control`
    /// max-age, which does not survive being handed to this crate).
    pub max_age_secs: i64,
}

impl GoogleStatusList {
    /// Freshness gate — the in-crate staleness check that closes the residual
    /// this module used to only document. Returns `Ok(())` while the fetched
    /// snapshot is still inside `[fetched_at, fetched_at + max_age]` relative to
    /// `now_unix`; otherwise fails **closed** with [`Verdict::Unverified`],
    /// exactly as `snp`'s [`crate::snp`] CRL check rejects a list whose
    /// `nextUpdate` has elapsed. A stale (aged-out) OR future-dated (negative
    /// age ⇒ clock skew) list proves nothing about *current* revocation state,
    /// so an enforcing caller must refetch rather than trust it.
    ///
    /// `now_unix` is the verifier's current time (seconds since the Unix
    /// epoch), passed explicitly — like `snp`'s `KdsCrl::now_unix` — so
    /// freshness is deterministic and unit-testable with no ambient clock.
    pub fn check_freshness(&self, now_unix: i64) -> Result<(), Verdict> {
        let expiry = self.fetched_at_unix.saturating_add(self.max_age_secs);
        if now_unix >= self.fetched_at_unix && now_unix <= expiry {
            Ok(())
        } else {
            Err(Verdict::Unverified(
                "status list — stale (fetched_at + max_age elapsed, or fetched in the future); \
                 refetch Google's attestation status list before trusting revocation state",
            ))
        }
    }

    /// Is `serial` (raw serial bytes of a chain cert) listed as revoked?
    fn revokes(&self, serial: &[u8]) -> bool {
        self.revoked_serials.iter().any(|s| s.as_slice() == serial)
    }
}

/// How a caller wants Android Key-Attestation **revocation** handled — the
/// mobile analogue of [`crate::snp`]'s `RevocationPolicy`. Safe-by-default in
/// the same sense: a caller MUST pick one arm by name, so "did nothing special"
/// can never silently accept a revoked device key.
#[derive(Debug, Clone, Copy)]
pub enum MobileRevocationPolicy<'a> {
    /// Enforce against a caller-fetched [`GoogleStatusList`]: run the in-crate
    /// [`GoogleStatusList::check_freshness`] gate first (a stale list is
    /// [`Verdict::Unverified`], fail closed), then reject any chain whose leaf
    /// serial is revoked ([`Verdict::Mismatch`]). The production choice.
    Enforce(&'a GoogleStatusList),
    /// Loudly-named opt-out — parity with `RevocationPolicy::
    /// SkipRevocationCheckDangerously`. NOT the default; a revoked key WILL
    /// pass. Only for deployments that accept the risk explicitly.
    SkipRevocationCheckDangerously,
}

/// Apply a [`MobileRevocationPolicy`] to an already-authenticated leaf serial.
/// Split out (parallel to `snp`'s `check_kds_crl`) so the freshness + serial
/// logic is unit-testable in isolation and so the verify entry point stays a
/// thin composition. `leaf_serial` is the leaf cert's `raw_serial()` bytes;
/// `now_unix` is the verifier's current time for the freshness gate.
pub fn check_status_list(
    policy: &MobileRevocationPolicy,
    leaf_serial: &[u8],
    now_unix: i64,
) -> Result<(), Verdict> {
    match policy {
        MobileRevocationPolicy::SkipRevocationCheckDangerously => Ok(()),
        MobileRevocationPolicy::Enforce(list) => {
            // Freshness FIRST: a stale list cannot even be trusted to say
            // "not revoked", so refuse it before consulting its contents.
            list.check_freshness(now_unix)?;
            if list.revokes(leaf_serial) {
                return Err(Verdict::Mismatch(
                    "status list — leaf key serial is revoked by Google's attestation status list",
                ));
            }
            Ok(())
        }
    }
}

// ── public API ─────────────────────────────────────────────────────────────

/// Verify an Android Key-Attestation certificate chain and return the shared
/// [`crate::Verdict`]. `chain_der` is **leaf-first** (index 0 is the attested
/// key's leaf cert). See [`verify_key_attestation_detailed`] for the parsed
/// tier on success.
pub fn verify_key_attestation(chain_der: &[&[u8]], expected: &MobileExpected) -> Verdict {
    match verify_key_attestation_detailed(chain_der, expected) {
        Ok(_) => Verdict::Genuine,
        Err(v) => v,
    }
}

/// Like [`verify_key_attestation`] PLUS a [`MobileRevocationPolicy`] gate — the
/// mobile analogue of `snp`'s `verify_snp_report(..., revocation, now_unix)`.
/// The chain is validated in full first (so a revocation `Verdict` always
/// concerns a leaf that already chained to a pinned Google root), and only then
/// is the leaf serial checked against the caller's policy via
/// [`check_status_list`] — including the in-crate freshness gate, so an
/// enforcing caller cannot accept an aged-out status list. `now_unix` is the
/// verifier's current time (seconds since the Unix epoch) for that gate.
pub fn verify_key_attestation_with_revocation(
    chain_der: &[&[u8]],
    expected: &MobileExpected,
    revocation: &MobileRevocationPolicy,
    now_unix: i64,
) -> Verdict {
    if let Err(v) = verify_key_attestation_detailed(chain_der, expected) {
        return v;
    }
    // The chain parsed and authenticated above, so chain_der is non-empty and
    // the leaf reparses; treat an unexpected parse failure as fail-closed.
    let leaf_serial = match X509Certificate::from_der(chain_der[0]) {
        Ok((_, leaf)) => leaf.raw_serial().to_vec(),
        Err(_) => return Verdict::Mismatch("certificate parse — malformed DER in the chain"),
    };
    match check_status_list(revocation, &leaf_serial, now_unix) {
        Ok(()) => Verdict::Genuine,
        Err(v) => v,
    }
}

/// Like [`verify_key_attestation`] but returns the authenticated
/// [`MobileAttestation`] on success (for tier reporting), or the fail-closed
/// [`Verdict`] on any failure.
pub fn verify_key_attestation_detailed(
    chain_der: &[&[u8]],
    expected: &MobileExpected,
) -> Result<MobileAttestation, Verdict> {
    // Anchor first: no pinned root ⇒ nothing authenticates ⇒ fail closed
    // (mirrors verify_report's no-trust-anchor path).
    if expected.roots.is_empty() {
        return Err(Verdict::Unverified(
            "no pinned attestation root — an Android Key-Attestation chain can only be trusted \
             against a caller-pinned Google root; refusing to trust the chain's own terminal cert",
        ));
    }
    if chain_der.is_empty() {
        return Err(Verdict::Mismatch("empty certificate chain"));
    }
    // Chain-length guard (fail fast, before any DER parse/crypto): real
    // Android Key-Attestation chains are 3-4 certs (leaf, one or two
    // intermediates, root). MAX_CHAIN_LEN is a generous sanity ceiling
    // against a pathologically long caller-supplied chain — unbounded
    // length would mean unbounded parse + signature-verify work per call.
    if chain_der.len() > MAX_CHAIN_LEN {
        return Err(Verdict::Mismatch("chain length — certificate chain exceeds the sane maximum"));
    }

    // 1. Parse every cert in the presented chain (leaf-first).
    let mut chain: Vec<X509Certificate> = Vec::with_capacity(chain_der.len());
    for der in chain_der {
        let (_, cert) = X509Certificate::from_der(der)
            .map_err(|_| Verdict::Mismatch("certificate parse — malformed DER in the chain"))?;
        chain.push(cert);
    }

    // 2. Validity windows (if a clock was supplied): every chain cert must be
    //    currently valid.
    if let Some(now) = expected.now_unix {
        let now = ASN1Time::from_timestamp(now)
            .map_err(|_| Verdict::Mismatch("invalid verifier clock"))?;
        for cert in &chain {
            if !cert.validity().is_valid_at(now) {
                return Err(Verdict::Mismatch("certificate validity — a chain cert is expired or not yet valid"));
            }
        }
    }

    // 3. Internal chain links: each cert signed by the next one up. This is
    //    a CRYPTOGRAPHIC linkage check only (cert i's signature verifies
    //    under cert i+1's public key) — it does NOT by itself prove cert i+1
    //    was AUTHORIZED to issue certificates. Step 3b closes that gap.
    for pair in chain.windows(2) {
        let issuer_pki = pair[1].public_key();
        if pair[0].verify_signature(Some(issuer_pki)).is_err() {
            return Err(Verdict::Mismatch("chain signature — a certificate is not signed by its issuer"));
        }
    }

    // 3b. Chain-direction / issuer-authorization hardening: every certificate
    //     ABOVE the leaf (index 1..) must carry BasicConstraints CA:true.
    //     Signature linkage alone (step 3) is not a chain-direction
    //     guarantee: any certificate whose private key is reachable —
    //     including a non-CA end-entity cert never authorized to issue
    //     further certificates — can cryptographically "sign" another cert.
    //     A cert with no CA:true was never meant to be an issuer; treating
    //     one as an intermediate anyway would let an attacker who obtains
    //     ANY signing-capable non-CA key splice a forged leaf into an
    //     otherwise-real chain. Missing/absent BasicConstraints ⇒ not a CA
    //     ⇒ rejected (fail closed, matches every other check in this path).
    for cert in &chain[1..] {
        let is_ca = cert
            .basic_constraints()
            .ok()
            .flatten()
            .map(|bc| bc.value.ca)
            .unwrap_or(false);
        if !is_ca {
            return Err(Verdict::Mismatch(
                "issuer constraint — a non-leaf certificate in the chain is not marked as a CA",
            ));
        }
    }

    // 4. Terminal cert must chain to a PINNED Google root: equal to a pinned
    //    root's DER, or signed by a pinned root's key. The wire never supplies
    //    the anchor.
    let top_der = chain_der[chain_der.len() - 1];
    let top = &chain[chain.len() - 1];
    let mut anchored = false;
    for root_der in &expected.roots {
        if root_der.as_slice() == top_der {
            anchored = true;
            break;
        }
        if let Ok((_, root)) = X509Certificate::from_der(root_der) {
            if top.verify_signature(Some(root.public_key())).is_ok() {
                anchored = true;
                break;
            }
        }
    }
    if !anchored {
        return Err(Verdict::Mismatch(
            "trust anchor — chain does not terminate at a pinned Google attestation root",
        ));
    }

    // 5. Extract the Key-Attestation extension from the LEAF and parse it.
    let leaf = &chain[0];
    let ext = leaf
        .extensions()
        .iter()
        .find(|e| e.oid.as_bytes() == KEY_ATTESTATION_OID)
        .ok_or(Verdict::Mismatch(
            "no attestation extension — leaf carries no Android Key-Attestation record",
        ))?;
    let kd = parse_key_description(ext.value)
        .map_err(Verdict::Mismatch)?;

    // 6. Field checks (nonce, boot state, patch level, app id, security level).
    evaluate(&kd, expected)
}

// ── parsed KeyDescription ──────────────────────────────────────────────────

/// The fields of a KeyMint/Keymaster `KeyDescription` we act on. `root_*` and
/// `os_patch_level` are taken from the **hardware-enforced** (`teeEnforced`)
/// list only; the app identity comes from `softwareEnforced` (where the OS
/// records it).
#[derive(Debug, Clone, Default)]
struct KeyDescription {
    attestation_security_level: u64,
    challenge: Vec<u8>,
    device_locked: Option<bool>,
    verified_boot_state: Option<u64>,
    os_patch_level: Option<u64>,
    package_names: Vec<String>,
    signature_digests: Vec<Vec<u8>>,
}

/// The subset of an `AuthorizationList` we care about.
#[derive(Debug, Clone, Default)]
struct AuthzList {
    device_locked: Option<bool>,
    verified_boot_state: Option<u64>,
    os_patch_level: Option<u64>,
    package_names: Vec<String>,
    signature_digests: Vec<Vec<u8>>,
}

/// Take the next DER TLV from `input`, returning it and the remainder.
fn take(input: &[u8]) -> Result<(Any<'_>, &[u8]), &'static str> {
    Any::from_der(input)
        .map(|(rest, any)| (any, rest))
        .map_err(|_| "attestation extension — malformed DER")
}

/// Big-endian unsigned interpretation of an INTEGER/ENUMERATED content, capped
/// at 8 bytes and rejecting a negative (high-bit-set) leading byte.
fn as_uint(any: &Any) -> Result<u64, &'static str> {
    let mut b = any.data;
    // DER may prepend a single 0x00 to keep a value positive; drop it.
    if b.first() == Some(&0x00) {
        b = &b[1..];
    }
    if b.is_empty() {
        return Ok(0);
    }
    if b.len() > 8 || b[0] & 0x80 != 0 {
        return Err("attestation extension — integer out of range");
    }
    let mut v: u64 = 0;
    for &byte in b {
        v = (v << 8) | byte as u64;
    }
    Ok(v)
}

/// Parse the leaf's KeyDescription extension value (DER).
fn parse_key_description(der: &[u8]) -> Result<KeyDescription, &'static str> {
    let (outer, _) = take(der)?;
    if outer.class() != Class::Universal || outer.tag() != Tag::Sequence {
        return Err("attestation extension — KeyDescription is not a SEQUENCE");
    }
    let mut cur = outer.data;
    let mut kd = KeyDescription::default();

    // Positional fields per the KeyMint/Keymaster schema.
    // 0: attestationVersion (INTEGER)
    let (_v, rest) = take(cur)?;
    cur = rest;
    // 1: attestationSecurityLevel (ENUMERATED)
    let (sl, rest) = take(cur)?;
    kd.attestation_security_level = as_uint(&sl)?;
    cur = rest;
    // 2: keymasterVersion (INTEGER)
    let (_kv, rest) = take(cur)?;
    cur = rest;
    // 3: keymasterSecurityLevel (ENUMERATED)
    let (_ksl, rest) = take(cur)?;
    cur = rest;
    // 4: attestationChallenge (OCTET STRING)
    let (chal, rest) = take(cur)?;
    if chal.tag() != Tag::OctetString {
        return Err("attestation extension — attestationChallenge is not an OCTET STRING");
    }
    kd.challenge = chal.data.to_vec();
    cur = rest;
    // 5: uniqueId (OCTET STRING) — ignored.
    let (_uid, rest) = take(cur)?;
    cur = rest;
    // 6: softwareEnforced (AuthorizationList)
    let (sw, rest) = take(cur)?;
    let sw = parse_authorization_list(&sw)?;
    cur = rest;
    // 7: teeEnforced (AuthorizationList)
    let (tee, _rest) = take(cur)?;
    let tee = parse_authorization_list(&tee)?;

    // Hardware-enforced facts from teeEnforced; app identity from software.
    kd.device_locked = tee.device_locked;
    kd.verified_boot_state = tee.verified_boot_state;
    kd.os_patch_level = tee.os_patch_level;
    kd.package_names = if sw.package_names.is_empty() { tee.package_names } else { sw.package_names };
    kd.signature_digests =
        if sw.signature_digests.is_empty() { tee.signature_digests } else { sw.signature_digests };
    Ok(kd)
}

/// Scan an `AuthorizationList` SEQUENCE for the context-tagged fields we use.
fn parse_authorization_list(seq: &Any) -> Result<AuthzList, &'static str> {
    if seq.class() != Class::Universal || seq.tag() != Tag::Sequence {
        return Err("attestation extension — AuthorizationList is not a SEQUENCE");
    }
    let mut out = AuthzList::default();
    let mut cur = seq.data;
    while !cur.is_empty() {
        let (elem, rest) = take(cur)?;
        cur = rest;
        if elem.class() != Class::ContextSpecific {
            continue;
        }
        match elem.tag().0 {
            TAG_ROOT_OF_TRUST => {
                // [704] EXPLICIT RootOfTrust ::= SEQUENCE {
                //   verifiedBootKey OCTET_STRING, deviceLocked BOOLEAN,
                //   verifiedBootState ENUMERATED, verifiedBootHash OCTET_STRING }
                let (rot, _) = take(elem.data)?;
                if rot.class() != Class::Universal || rot.tag() != Tag::Sequence {
                    return Err("attestation extension — RootOfTrust is not a SEQUENCE");
                }
                let mut r = rot.data;
                let (_vbkey, r1) = take(r)?;
                r = r1;
                let (locked, r2) = take(r)?;
                if locked.tag() != Tag::Boolean {
                    return Err("attestation extension — deviceLocked is not a BOOLEAN");
                }
                out.device_locked = Some(locked.data.iter().any(|&b| b != 0));
                r = r2;
                let (vbstate, _) = take(r)?;
                out.verified_boot_state = Some(as_uint(&vbstate)?);
            }
            TAG_OS_PATCH_LEVEL => {
                let (v, _) = take(elem.data)?;
                out.os_patch_level = Some(as_uint(&v)?);
            }
            TAG_ATTESTATION_APPLICATION_ID => {
                // [709] EXPLICIT OCTET_STRING, whose content is a DER
                // AttestationApplicationId.
                let (os, _) = take(elem.data)?;
                if os.tag() != Tag::OctetString {
                    return Err("attestation extension — AttestationApplicationId is not an OCTET STRING");
                }
                let (names, digests) = parse_attestation_application_id(os.data)?;
                out.package_names = names;
                out.signature_digests = digests;
            }
            _ => {}
        }
    }
    Ok(out)
}

/// Parse `AttestationApplicationId ::= SEQUENCE { SET OF AttestationPackageInfo,
/// SET OF OCTET_STRING signatureDigests }`, where
/// `AttestationPackageInfo ::= SEQUENCE { OCTET_STRING packageName, INTEGER version }`.
fn parse_attestation_application_id(der: &[u8]) -> Result<(Vec<String>, Vec<Vec<u8>>), &'static str> {
    let (outer, _) = take(der)?;
    if outer.class() != Class::Universal || outer.tag() != Tag::Sequence {
        return Err("attestation extension — AttestationApplicationId is not a SEQUENCE");
    }
    let mut cur = outer.data;
    // packageInfos: SET OF SEQUENCE { OCTET_STRING name, INTEGER version }
    let (pkg_set, rest) = take(cur)?;
    cur = rest;
    let mut names = Vec::new();
    let mut p = pkg_set.data;
    while !p.is_empty() {
        let (info, r) = take(p)?;
        p = r;
        if info.tag() != Tag::Sequence {
            continue;
        }
        let (name, _) = take(info.data)?;
        if name.tag() == Tag::OctetString {
            if let Ok(s) = core::str::from_utf8(name.data) {
                names.push(s.to_string());
            }
        }
    }
    // signatureDigests: SET OF OCTET_STRING
    let mut digests = Vec::new();
    if !cur.is_empty() {
        let (dig_set, _) = take(cur)?;
        let mut d = dig_set.data;
        while !d.is_empty() {
            let (dg, r) = take(d)?;
            d = r;
            if dg.tag() == Tag::OctetString {
                digests.push(dg.data.to_vec());
            }
        }
    }
    Ok((names, digests))
}

// ── field evaluation (no crypto — unit-testable in isolation) ──────────────

/// Apply the [`MobileExpected`] policy to a parsed [`KeyDescription`]. Every
/// check is fail-closed with a named reason.
fn evaluate(kd: &KeyDescription, expected: &MobileExpected) -> Result<MobileAttestation, Verdict> {
    // Nonce freshness — constant-time-ish equal is unnecessary (public value),
    // but exact match is required.
    if kd.challenge != expected.challenge {
        return Err(Verdict::Mismatch("nonce — attestation challenge does not match the issued nonce"));
    }

    // Security level floor.
    let level = SecurityLevel::from_enum(kd.attestation_security_level)
        .ok_or(Verdict::Mismatch("security level — unknown attestation SecurityLevel"))?;
    if level < expected.min_security_level {
        return Err(Verdict::Mismatch("security level — key is below the required hardware tier"));
    }

    // Verified-boot / device-locked (hardware-enforced RootOfTrust).
    let vbstate_raw = kd
        .verified_boot_state
        .ok_or(Verdict::Mismatch("root of trust — no verifiedBootState in the hardware-enforced list"))?;
    let vbstate = VerifiedBootState::from_enum(vbstate_raw)
        .ok_or(Verdict::Mismatch("root of trust — unknown verifiedBootState"))?;
    let device_locked = kd
        .device_locked
        .ok_or(Verdict::Mismatch("root of trust — no deviceLocked in the hardware-enforced list"))?;

    if expected.require_verified_boot && vbstate != VerifiedBootState::Verified {
        return Err(Verdict::Mismatch("verified boot — device is not in the Verified boot state"));
    }
    if expected.require_device_locked && !device_locked {
        return Err(Verdict::Mismatch("device locked — bootloader is unlocked"));
    }

    // OS patch-level anti-rollback.
    if let Some(min) = expected.min_os_patch_level {
        let got = kd
            .os_patch_level
            .ok_or(Verdict::Mismatch("os patch level — not reported but a minimum is required"))?;
        if (got as u32) < min {
            return Err(Verdict::Mismatch("os patch level — device firmware below the accepted minimum"));
        }
    }

    // Attesting-app identity: every expected package + digest must be present.
    if let Some(app) = &expected.expected_app {
        for want in &app.package_names {
            if !kd.package_names.iter().any(|p| p == want) {
                return Err(Verdict::Mismatch("app identity — attesting package is not the expected app"));
            }
        }
        for want in &app.signature_digests {
            if !kd.signature_digests.iter().any(|d| d == want) {
                return Err(Verdict::Mismatch("app identity — attesting app signing cert is not the expected one"));
            }
        }
    }

    Ok(MobileAttestation {
        security_level: level,
        device_locked,
        verified_boot_state: vbstate,
        os_patch_level: kd.os_patch_level.map(|v| v as u32),
        package_names: kd.package_names.clone(),
        signature_digests: kd.signature_digests.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── tiny DER encoders (build KeyDescription vectors by hand) ───────────

    fn der_len(n: usize) -> Vec<u8> {
        if n < 0x80 {
            vec![n as u8]
        } else {
            let mut b = Vec::new();
            let mut v = n;
            while v > 0 {
                b.insert(0, (v & 0xFF) as u8);
                v >>= 8;
            }
            let mut out = vec![0x80 | b.len() as u8];
            out.extend(b);
            out
        }
    }

    /// TLV with an explicit single tag byte (universal primitives/constructed).
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend(der_len(content.len()));
        out.extend_from_slice(content);
        out
    }

    fn int(v: u64) -> Vec<u8> {
        if v == 0 {
            return tlv(0x02, &[0x00]);
        }
        let mut b = Vec::new();
        let mut x = v;
        while x > 0 {
            b.insert(0, (x & 0xFF) as u8);
            x >>= 8;
        }
        if b[0] & 0x80 != 0 {
            b.insert(0, 0x00);
        }
        tlv(0x02, &b)
    }

    fn enumerated(v: u8) -> Vec<u8> {
        tlv(0x0A, &[v])
    }
    fn octet(v: &[u8]) -> Vec<u8> {
        tlv(0x04, v)
    }
    fn boolean(b: bool) -> Vec<u8> {
        tlv(0x01, &[if b { 0xFF } else { 0x00 }])
    }
    fn sequence(inner: &[u8]) -> Vec<u8> {
        tlv(0x30, inner)
    }
    fn set(inner: &[u8]) -> Vec<u8> {
        tlv(0x31, inner)
    }

    /// Context-specific constructed [tagnum] EXPLICIT wrapper (long-form tag
    /// for tagnum > 30 — exercises the real high-tag encoding).
    fn ctx(tagnum: u32, inner: &[u8]) -> Vec<u8> {
        let mut tagbytes = Vec::new();
        if tagnum <= 30 {
            tagbytes.push(0xA0 | tagnum as u8);
        } else {
            tagbytes.push(0xBF); // context, constructed, high-tag form
            let mut base128 = Vec::new();
            let mut v = tagnum;
            base128.insert(0, (v & 0x7F) as u8);
            v >>= 7;
            while v > 0 {
                base128.insert(0, ((v & 0x7F) as u8) | 0x80);
                v >>= 7;
            }
            tagbytes.extend(base128);
        }
        let mut out = tagbytes;
        out.extend(der_len(inner.len()));
        out.extend_from_slice(inner);
        out
    }

    fn app_id(package: &str, digest: &[u8]) -> Vec<u8> {
        let pkg_info = sequence(&[octet(package.as_bytes()), int(1)].concat());
        let pkg_set = set(&pkg_info);
        let dig_set = set(&octet(digest));
        sequence(&[pkg_set, dig_set].concat())
    }

    fn root_of_trust(locked: bool, vbstate: u8) -> Vec<u8> {
        sequence(
            &[
                octet(&[0u8; 32]), // verifiedBootKey
                boolean(locked),
                enumerated(vbstate),
                octet(&[0u8; 32]), // verifiedBootHash
            ]
            .concat(),
        )
    }

    /// Build a full KeyDescription DER with the supplied knobs.
    fn key_description(
        sec_level: u8,
        challenge: &[u8],
        locked: bool,
        vbstate: u8,
        patch: u64,
        package: &str,
        digest: &[u8],
    ) -> Vec<u8> {
        let software = sequence(&ctx(TAG_ATTESTATION_APPLICATION_ID, &octet(&app_id(package, digest))));
        let tee = sequence(
            &[
                ctx(TAG_ROOT_OF_TRUST, &root_of_trust(locked, vbstate)),
                ctx(TAG_OS_PATCH_LEVEL, &int(patch)),
            ]
            .concat(),
        );
        sequence(
            &[
                int(200),              // attestationVersion
                enumerated(sec_level), // attestationSecurityLevel
                int(4),                // keymasterVersion
                enumerated(sec_level), // keymasterSecurityLevel
                octet(challenge),      // attestationChallenge
                octet(&[]),            // uniqueId
                software,
                tee,
            ]
            .concat(),
        )
    }

    fn base_expected() -> MobileExpected {
        MobileExpected {
            roots: vec![vec![0xDE, 0xAD]], // non-empty so the anchor gate is passed at the evaluate layer
            challenge: vec![1, 2, 3, 4],
            require_device_locked: true,
            require_verified_boot: true,
            min_security_level: SecurityLevel::StrongBox,
            min_os_patch_level: Some(202401),
            expected_app: Some(AppIdentity {
                package_names: vec!["labs.postern.wallet".into()],
                signature_digests: vec![vec![0xAB; 32]],
            }),
            now_unix: None,
        }
    }

    fn parse_and_eval(der: &[u8], exp: &MobileExpected) -> Verdict {
        match parse_key_description(der).map_err(Verdict::Mismatch).and_then(|kd| evaluate(&kd, exp)) {
            Ok(_) => Verdict::Genuine,
            Err(v) => v,
        }
    }

    #[test]
    fn happy_path_strongbox_verified_locked() {
        let der = key_description(2, &[1, 2, 3, 4], true, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);
        assert_eq!(parse_and_eval(&der, &base_expected()), Verdict::Genuine);
    }

    #[test]
    fn nonce_mismatch_is_caught() {
        let der = key_description(2, &[9, 9, 9, 9], true, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);
        assert_eq!(
            parse_and_eval(&der, &base_expected()),
            Verdict::Mismatch("nonce — attestation challenge does not match the issued nonce")
        );
    }

    #[test]
    fn unlocked_bootloader_is_rejected() {
        // deviceLocked = false, verifiedBootState = Unverified(2).
        let der = key_description(2, &[1, 2, 3, 4], false, 2, 202401, "labs.postern.wallet", &[0xAB; 32]);
        // require_verified_boot fails first.
        assert_eq!(
            parse_and_eval(&der, &base_expected()),
            Verdict::Mismatch("verified boot — device is not in the Verified boot state")
        );
    }

    #[test]
    fn device_locked_false_but_verified_state_still_rejected_on_lock() {
        let mut exp = base_expected();
        exp.require_verified_boot = false; // isolate the device-locked check
        let der = key_description(2, &[1, 2, 3, 4], false, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);
        assert_eq!(
            parse_and_eval(&der, &exp),
            Verdict::Mismatch("device locked — bootloader is unlocked")
        );
    }

    #[test]
    fn stale_patch_level_is_rejected() {
        let der = key_description(2, &[1, 2, 3, 4], true, 0, 202301, "labs.postern.wallet", &[0xAB; 32]);
        assert_eq!(
            parse_and_eval(&der, &base_expected()),
            Verdict::Mismatch("os patch level — device firmware below the accepted minimum")
        );
    }

    #[test]
    fn tee_only_below_required_strongbox_is_rejected() {
        // attestationSecurityLevel = TrustedEnvironment(1) < required StrongBox.
        let der = key_description(1, &[1, 2, 3, 4], true, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);
        assert_eq!(
            parse_and_eval(&der, &base_expected()),
            Verdict::Mismatch("security level — key is below the required hardware tier")
        );
    }

    #[test]
    fn tee_tier_accepted_when_floor_is_tee() {
        let mut exp = base_expected();
        exp.min_security_level = SecurityLevel::TrustedEnvironment;
        let der = key_description(1, &[1, 2, 3, 4], true, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);
        assert_eq!(parse_and_eval(&der, &exp), Verdict::Genuine);
    }

    #[test]
    fn wrong_package_is_rejected() {
        let der = key_description(2, &[1, 2, 3, 4], true, 0, 202401, "com.evil.app", &[0xAB; 32]);
        assert_eq!(
            parse_and_eval(&der, &base_expected()),
            Verdict::Mismatch("app identity — attesting package is not the expected app")
        );
    }

    #[test]
    fn wrong_signing_digest_is_rejected() {
        let der = key_description(2, &[1, 2, 3, 4], true, 0, 202401, "labs.postern.wallet", &[0xCD; 32]);
        assert_eq!(
            parse_and_eval(&der, &base_expected()),
            Verdict::Mismatch("app identity — attesting app signing cert is not the expected one")
        );
    }

    #[test]
    fn detailed_tier_is_reported_on_success() {
        let der = key_description(2, &[1, 2, 3, 4], true, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);
        let kd = parse_key_description(&der).unwrap();
        let att = evaluate(&kd, &base_expected()).unwrap();
        assert_eq!(att.security_level, SecurityLevel::StrongBox);
        assert!(att.device_locked);
        assert_eq!(att.verified_boot_state, VerifiedBootState::Verified);
        assert_eq!(att.os_patch_level, Some(202401));
        assert_eq!(att.package_names, vec!["labs.postern.wallet".to_string()]);
    }

    #[test]
    fn no_pinned_root_fails_closed() {
        let mut exp = base_expected();
        exp.roots = vec![];
        // Full entry point: even a well-formed (but here empty) chain must fail
        // closed when no root is pinned.
        let v = verify_key_attestation_detailed(&[], &exp).unwrap_err();
        assert!(matches!(v, Verdict::Unverified(_)));
    }

    #[test]
    fn empty_chain_with_roots_is_mismatch() {
        let v = verify_key_attestation(&[], &base_expected());
        assert_eq!(v, Verdict::Mismatch("empty certificate chain"));
    }

    #[test]
    fn garbage_der_leaf_is_rejected() {
        let exp = base_expected();
        let garbage: &[u8] = &[0x00, 0x01, 0x02, 0x03];
        let v = verify_key_attestation(&[garbage], &exp);
        assert_eq!(v, Verdict::Mismatch("certificate parse — malformed DER in the chain"));
    }

    #[test]
    fn malformed_key_description_is_rejected() {
        // Not a SEQUENCE at the top.
        let der = octet(&[1, 2, 3]);
        assert!(matches!(parse_key_description(&der), Err(_)));
    }

    #[test]
    fn high_tag_encoding_roundtrips() {
        // Sanity: our ctx() long-form encoder produces a parseable context tag
        // whose number the parser reads back exactly (704 is the tricky one).
        let inner = int(202401);
        let wrapped = ctx(TAG_OS_PATCH_LEVEL, &inner);
        let (any, _) = take(&wrapped).unwrap();
        assert_eq!(any.class(), Class::ContextSpecific);
        assert_eq!(any.tag().0, TAG_OS_PATCH_LEVEL);
    }

    // ── added negative vectors (evaluate layer) ───────────────────────────
    // These close the gaps the Wave-1 plan §5 names explicitly: a
    // software-only keymaster, an unlocked/self-signed bootloader, and a
    // replayed (stale) nonce must all produce the correct NON-Genuine verdict.

    #[test]
    fn software_keymaster_below_hardware_tier_is_rejected() {
        // attestationSecurityLevel = Software(0): a software-only keymaster —
        // what an emulator or a non-hardware-backed key reports. It never meets
        // the StrongBox hardware floor. (`vector-tested ≠ attested`.)
        let der = key_description(0, &[1, 2, 3, 4], true, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);
        assert_eq!(
            parse_and_eval(&der, &base_expected()),
            Verdict::Mismatch("security level — key is below the required hardware tier")
        );
    }

    #[test]
    fn software_keymaster_rejected_even_when_floor_is_tee() {
        // Software(0) is below EVEN the TEE-fallback tier: the graceful fallback
        // must never silently accept a software attestation as hardware-backed.
        let mut exp = base_expected();
        exp.min_security_level = SecurityLevel::TrustedEnvironment;
        let der = key_description(0, &[1, 2, 3, 4], true, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);
        assert_eq!(
            parse_and_eval(&der, &exp),
            Verdict::Mismatch("security level — key is below the required hardware tier")
        );
    }

    #[test]
    fn unlocked_bootloader_selfsigned_is_rejected() {
        // Realistic custom-ROM / unlocked-bootloader posture: verifiedBootState =
        // SelfSigned(1) (a user-installed root of trust) AND deviceLocked = false.
        // The verified-boot floor rejects it — a required, honest non-Genuine.
        let der = key_description(2, &[1, 2, 3, 4], false, 1, 202401, "labs.postern.wallet", &[0xAB; 32]);
        assert_eq!(
            parse_and_eval(&der, &base_expected()),
            Verdict::Mismatch("verified boot — device is not in the Verified boot state")
        );
    }

    #[test]
    fn replayed_stale_nonce_is_rejected() {
        // Replay: an attestation minted in a PRIOR session (challenge [7,7,7,7])
        // is replayed against THIS session's freshly-issued nonce ([1,2,3,4] in
        // base_expected). The challenge-echo check fails → Mismatch (anti-replay).
        let stale = key_description(2, &[7, 7, 7, 7], true, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);
        assert_eq!(
            parse_and_eval(&stale, &base_expected()),
            Verdict::Mismatch("nonce — attestation challenge does not match the issued nonce")
        );
    }

    // ── real-chain vectors (rcgen): the FULL verify_key_attestation path ───
    // The tests above drive parse_key_description + evaluate directly. These
    // build a REAL leaf←intermediate←root ECDSA-P256 chain (the same rcgen
    // test-cert pattern the tdx/snp vectors use) with the Key-Attestation
    // extension embedded in the leaf, then drive the FULL public entry point —
    // chain parse + per-link signature verification + pinned-root anchoring —
    // so "wrong root" and "broken chain link" are proven end-to-end, not just
    // at the field-evaluation layer. Still `vector-tested ≠ attested`: no real
    // StrongBox ever minted these certs.

    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, IsCa, KeyPair, KeyUsagePurpose,
        PKCS_ECDSA_P256_SHA256,
    };

    /// DER OID arcs of `1.3.6.1.4.1.11129.2.1.17` (Android Key Attestation).
    const ATT_OID_ARCS: &[u64] = &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17];

    struct RealChain {
        leaf: Vec<u8>,
        inter: Vec<u8>,
        root: Vec<u8>,
    }

    /// Build `leaf(+KeyDescription ext) ← intermediate ← self-signed root`, all
    /// ECDSA P-256, returning each cert DER. Presented leaf-first as
    /// `[leaf, inter, root]` — the A↔C wire order the verifier consumes.
    fn real_attested_chain(kd_der: &[u8]) -> RealChain {
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut rp = CertificateParams::new(vec!["Postern Test Attestation Root".into()]).unwrap();
        rp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        rp.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let root = rp.self_signed(&root_key).unwrap();

        let inter_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ip =
            CertificateParams::new(vec!["Postern Test Attestation Intermediate".into()]).unwrap();
        ip.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ip.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let inter = ip.signed_by(&inter_key, &root, &root_key).unwrap();

        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut lp = CertificateParams::new(vec!["Android Keystore Attested Key".into()]).unwrap();
        lp.custom_extensions
            .push(CustomExtension::from_oid_content(ATT_OID_ARCS, kd_der.to_vec()));
        let leaf = lp.signed_by(&leaf_key, &inter, &inter_key).unwrap();

        RealChain {
            leaf: leaf.der().as_ref().to_vec(),
            inter: inter.der().as_ref().to_vec(),
            root: root.der().as_ref().to_vec(),
        }
    }

    /// `base_expected` but pinning `root_der` and skipping the wall-clock window
    /// (rcgen's default validity is fine; we isolate the anchor/eval logic).
    fn expected_pinning(root_der: Vec<u8>) -> MobileExpected {
        let mut e = base_expected();
        e.roots = vec![root_der];
        e.now_unix = None;
        e
    }

    #[test]
    fn full_path_genuine_through_real_chain() {
        let kd = key_description(2, &[1, 2, 3, 4], true, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);
        let c = real_attested_chain(&kd);
        let exp = expected_pinning(c.root.clone());
        let chain: Vec<&[u8]> = vec![&c.leaf, &c.inter, &c.root];
        assert_eq!(verify_key_attestation(&chain, &exp), Verdict::Genuine);
        // The detailed path reports the tier ACTUALLY attested (StrongBox) —
        // never upgraded past what the chain proves.
        let att = verify_key_attestation_detailed(&chain, &exp).unwrap();
        assert_eq!(att.security_level, SecurityLevel::StrongBox);
        assert!(att.device_locked);
        assert_eq!(att.verified_boot_state, VerifiedBootState::Verified);
    }

    // ── status-list freshness gate + revocation (mirrors snp's CRL check) ──
    // Google's status-list JSON carries no signed `nextUpdate`, so the operator
    // supplies fetched_at + max_age and the crate enforces the staleness bound
    // in-crate — the mobile analogue of snp's KdsCrl `nextUpdate` freshness.

    /// A list fetched at t=1000 that the operator trusts for 3600s.
    fn status_list(revoked: Vec<Vec<u8>>) -> GoogleStatusList {
        GoogleStatusList { revoked_serials: revoked, fetched_at_unix: 1000, max_age_secs: 3600 }
    }

    #[test]
    fn stale_status_list_fails_closed_unverified() {
        // now is well past fetched_at + max_age (1000 + 3600 = 4600) → the
        // snapshot is aged out; a fresh revocation could have landed since, so
        // the gate refuses it fail-CLOSED with Unverified (never Genuine),
        // exactly like snp rejecting a CRL whose nextUpdate has elapsed.
        let list = status_list(vec![]);
        assert!(matches!(list.check_freshness(9_999), Err(Verdict::Unverified(_))));
    }

    #[test]
    fn fresh_status_list_is_unchanged() {
        // now is inside [fetched_at, fetched_at + max_age] → the freshness gate
        // is a no-op; an empty (nothing-revoked) fresh list leaves the verdict
        // exactly as it was without any revocation policy.
        let list = status_list(vec![]);
        assert_eq!(list.check_freshness(2000), Ok(()));
        // And the isolated policy application agrees: a fresh, empty list does
        // not turn an otherwise-good leaf into anything but Ok.
        let policy = MobileRevocationPolicy::Enforce(&list);
        assert_eq!(check_status_list(&policy, &[0x11, 0x22], 2000), Ok(()));
    }

    #[test]
    fn future_dated_status_list_fails_closed() {
        // now BEFORE the recorded fetch instant is bogus clock skew — a list
        // "from the future" is not evidence of current state. Fail closed.
        let list = status_list(vec![]);
        assert!(matches!(list.check_freshness(500), Err(Verdict::Unverified(_))));
    }

    #[test]
    fn boundary_at_exact_expiry_is_still_fresh() {
        // Inclusive upper bound (now == fetched_at + max_age) is the last fresh
        // instant, mirroring snp's `now_unix <= nextUpdate`.
        let list = status_list(vec![]);
        assert_eq!(list.check_freshness(4600), Ok(()));
        assert!(matches!(list.check_freshness(4601), Err(Verdict::Unverified(_))));
    }

    #[test]
    fn enforce_stale_list_fails_closed_on_full_path() {
        // The gate is reachable through the real entry point, not just the
        // isolated helper: a genuine, well-anchored chain STILL fails closed
        // (Unverified) when the enforcing caller's status list is stale —
        // freshness is checked before the list's contents are trusted.
        let kd = key_description(2, &[1, 2, 3, 4], true, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);
        let c = real_attested_chain(&kd);
        let exp = expected_pinning(c.root.clone());
        let chain: Vec<&[u8]> = vec![&c.leaf, &c.inter, &c.root];
        // Sanity: without revocation this exact chain is Genuine.
        assert_eq!(verify_key_attestation(&chain, &exp), Verdict::Genuine);
        let list = status_list(vec![]);
        let policy = MobileRevocationPolicy::Enforce(&list);
        assert!(matches!(
            verify_key_attestation_with_revocation(&chain, &exp, &policy, 9_999),
            Verdict::Unverified(_)
        ));
    }

    #[test]
    fn enforce_fresh_list_leaves_genuine_unchanged_on_full_path() {
        // The complementary case: same chain, a FRESH empty list → the verdict
        // is unchanged (Genuine), proving the gate adds no false negative.
        let kd = key_description(2, &[1, 2, 3, 4], true, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);
        let c = real_attested_chain(&kd);
        let exp = expected_pinning(c.root.clone());
        let chain: Vec<&[u8]> = vec![&c.leaf, &c.inter, &c.root];
        let list = status_list(vec![]);
        let policy = MobileRevocationPolicy::Enforce(&list);
        assert_eq!(
            verify_key_attestation_with_revocation(&chain, &exp, &policy, 2000),
            Verdict::Genuine
        );
    }

    #[test]
    fn revoked_leaf_serial_is_mismatch_on_fresh_list() {
        // A FRESH list (passes the freshness gate) that lists the leaf's own
        // serial → the otherwise-genuine chain is rejected (Mismatch), so the
        // serial check is real and not masked by the freshness gate.
        let kd = key_description(2, &[1, 2, 3, 4], true, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);
        let c = real_attested_chain(&kd);
        let exp = expected_pinning(c.root.clone());
        let chain: Vec<&[u8]> = vec![&c.leaf, &c.inter, &c.root];
        let (_, leaf) = X509Certificate::from_der(&c.leaf).unwrap();
        let leaf_serial = leaf.raw_serial().to_vec();
        let list = status_list(vec![leaf_serial]);
        let policy = MobileRevocationPolicy::Enforce(&list);
        assert_eq!(
            verify_key_attestation_with_revocation(&chain, &exp, &policy, 2000),
            Verdict::Mismatch(
                "status list — leaf key serial is revoked by Google's attestation status list"
            )
        );
    }

    #[test]
    fn skip_dangerously_never_consults_the_list() {
        // The loud opt-out ignores the list entirely: even a stale list and a
        // revoked serial cannot turn the chain non-Genuine — that is the whole
        // (dangerous) point, and it must be asked for by name.
        let kd = key_description(2, &[1, 2, 3, 4], true, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);
        let c = real_attested_chain(&kd);
        let exp = expected_pinning(c.root.clone());
        let chain: Vec<&[u8]> = vec![&c.leaf, &c.inter, &c.root];
        assert_eq!(
            verify_key_attestation_with_revocation(
                &chain,
                &exp,
                &MobileRevocationPolicy::SkipRevocationCheckDangerously,
                9_999, // stale-era timestamp is irrelevant when skipping
            ),
            Verdict::Genuine
        );
    }

    #[test]
    fn wrong_root_is_rejected_full_path() {
        // A well-formed, internally-consistent chain — but pinned against a
        // DIFFERENT root than the one it terminates at → trust-anchor Mismatch.
        // (The wire can never supply its own anchor.)
        let kd = key_description(2, &[1, 2, 3, 4], true, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);
        let c = real_attested_chain(&kd);
        let other = real_attested_chain(&kd); // an unrelated self-signed root
        let exp = expected_pinning(other.root.clone());
        let chain: Vec<&[u8]> = vec![&c.leaf, &c.inter, &c.root];
        assert_eq!(
            verify_key_attestation(&chain, &exp),
            Verdict::Mismatch(
                "trust anchor — chain does not terminate at a pinned Google attestation root"
            )
        );
    }

    #[test]
    fn broken_chain_link_is_rejected_full_path() {
        // Present [leaf, root] OMITTING the intermediate that actually signed the
        // leaf → leaf is not signed by the presented issuer → chain-signature
        // Mismatch (caught before anchoring).
        let kd = key_description(2, &[1, 2, 3, 4], true, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);
        let c = real_attested_chain(&kd);
        let exp = expected_pinning(c.root.clone());
        let chain: Vec<&[u8]> = vec![&c.leaf, &c.root];
        assert_eq!(
            verify_key_attestation(&chain, &exp),
            Verdict::Mismatch("chain signature — a certificate is not signed by its issuer")
        );
    }

    // ── adversarial hardening vectors (Bucket B / Dev C) ────────────────────
    // Everything below is offline, synthetic (rcgen or hand-built DER), and
    // fails closed on purpose — no real StrongBox device was involved
    // (`vector-tested ≠ attested`, restated per module docs).

    #[test]
    fn oversized_chain_is_rejected() {
        // A pathologically long caller-supplied chain (attacker-controlled
        // input) must be rejected before any DER parsing/crypto work — a
        // DoS/sanity bound, not a realistic Android chain shape (those are
        // 3-4 certs).
        let exp = base_expected();
        let filler: &[u8] = &[0x30, 0x00]; // never reached — length check is first
        let chain: Vec<&[u8]> = vec![filler; MAX_CHAIN_LEN + 1];
        assert_eq!(
            verify_key_attestation(&chain, &exp),
            Verdict::Mismatch("chain length — certificate chain exceeds the sane maximum")
        );
    }

    #[test]
    fn non_ca_intermediate_is_rejected_full_path() {
        // Chain-direction / issuer-authorization hardening: rcgen's own docs
        // note "no validation of the issuer is performed" by `signed_by` — it
        // will happily let a certificate WITHOUT BasicConstraints CA:true
        // (`IsCa::NoCa`, rcgen's default) sign another certificate. Before
        // this hardening, the verifier's chain check was pure signature
        // linkage and would have accepted this. A cert never authorized to
        // issue certificates must not be usable as a chain link.
        let kd = key_description(2, &[1, 2, 3, 4], true, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);

        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut rp = CertificateParams::new(vec!["Postern Test Attestation Root".into()]).unwrap();
        rp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        rp.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let root = rp.self_signed(&root_key).unwrap();

        // NOT a CA: default IsCa::NoCa — no BasicConstraints CA:true extension.
        let inter_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let ip = CertificateParams::new(vec!["Not Actually A CA".into()]).unwrap();
        let inter = ip.signed_by(&inter_key, &root, &root_key).unwrap();

        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut lp = CertificateParams::new(vec!["Android Keystore Attested Key".into()]).unwrap();
        lp.custom_extensions
            .push(CustomExtension::from_oid_content(ATT_OID_ARCS, kd.clone()));
        let leaf = lp.signed_by(&leaf_key, &inter, &inter_key).unwrap();

        let leaf_der = leaf.der().as_ref().to_vec();
        let inter_der = inter.der().as_ref().to_vec();
        let root_der = root.der().as_ref().to_vec();
        let exp = expected_pinning(root_der.clone());
        let chain: Vec<&[u8]> = vec![&leaf_der, &inter_der, &root_der];
        assert_eq!(
            verify_key_attestation(&chain, &exp),
            Verdict::Mismatch("issuer constraint — a non-leaf certificate in the chain is not marked as a CA")
        );
    }

    #[test]
    fn patch_level_boundary_at_exactly_the_floor() {
        // Boundary extension of `stale_patch_level_is_rejected` (floor - 1):
        // floor - 1 must reject, the floor itself must accept (>=, not >).
        let below_floor =
            key_description(2, &[1, 2, 3, 4], true, 0, 202400, "labs.postern.wallet", &[0xAB; 32]);
        assert_eq!(
            parse_and_eval(&below_floor, &base_expected()),
            Verdict::Mismatch("os patch level — device firmware below the accepted minimum")
        );
        let at_floor =
            key_description(2, &[1, 2, 3, 4], true, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);
        assert_eq!(parse_and_eval(&at_floor, &base_expected()), Verdict::Genuine);
    }

    #[test]
    fn expired_leaf_cert_is_rejected_full_path() {
        // Explicit rcgen-built expired-cert case through the FULL entry point
        // (chain parse + validity window + signature + anchor). The hand-built
        // DER vectors above never set `now_unix`, so this is the first vector
        // that exercises the wall-clock validity check end to end rather than
        // only proving the field exists.
        let kd = key_description(2, &[1, 2, 3, 4], true, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);

        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut rp = CertificateParams::new(vec!["Postern Test Attestation Root".into()]).unwrap();
        rp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        rp.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let root = rp.self_signed(&root_key).unwrap();

        let inter_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ip =
            CertificateParams::new(vec!["Postern Test Attestation Intermediate".into()]).unwrap();
        ip.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ip.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let inter = ip.signed_by(&inter_key, &root, &root_key).unwrap();

        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut lp = CertificateParams::new(vec!["Android Keystore Attested Key".into()]).unwrap();
        // Long-expired validity window: 2020-09-13 .. 2021-09-13.
        lp.not_before = time::OffsetDateTime::from_unix_timestamp(1_600_000_000).unwrap();
        lp.not_after = time::OffsetDateTime::from_unix_timestamp(1_631_536_000).unwrap();
        lp.custom_extensions
            .push(CustomExtension::from_oid_content(ATT_OID_ARCS, kd.clone()));
        let leaf = lp.signed_by(&leaf_key, &inter, &inter_key).unwrap();

        let leaf_der = leaf.der().as_ref().to_vec();
        let inter_der = inter.der().as_ref().to_vec();
        let root_der = root.der().as_ref().to_vec();
        let mut exp = expected_pinning(root_der.clone());
        exp.now_unix = Some(1_700_000_000); // "now" is long after the leaf's not_after
        let chain: Vec<&[u8]> = vec![&leaf_der, &inter_der, &root_der];
        assert_eq!(
            verify_key_attestation(&chain, &exp),
            Verdict::Mismatch("certificate validity — a chain cert is expired or not yet valid")
        );
    }

    #[test]
    fn not_yet_valid_leaf_cert_is_rejected_full_path() {
        // The other half of the validity-window boundary: a cert whose
        // not_before is in the FUTURE relative to the verifier's clock.
        let kd = key_description(2, &[1, 2, 3, 4], true, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);

        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut rp = CertificateParams::new(vec!["Postern Test Attestation Root".into()]).unwrap();
        rp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        rp.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let root = rp.self_signed(&root_key).unwrap();

        let inter_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ip =
            CertificateParams::new(vec!["Postern Test Attestation Intermediate".into()]).unwrap();
        ip.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ip.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let inter = ip.signed_by(&inter_key, &root, &root_key).unwrap();

        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut lp = CertificateParams::new(vec!["Android Keystore Attested Key".into()]).unwrap();
        // Not valid until far in the future.
        lp.not_before = time::OffsetDateTime::from_unix_timestamp(2_000_000_000).unwrap();
        lp.not_after = time::OffsetDateTime::from_unix_timestamp(2_100_000_000).unwrap();
        lp.custom_extensions
            .push(CustomExtension::from_oid_content(ATT_OID_ARCS, kd.clone()));
        let leaf = lp.signed_by(&leaf_key, &inter, &inter_key).unwrap();

        let leaf_der = leaf.der().as_ref().to_vec();
        let inter_der = inter.der().as_ref().to_vec();
        let root_der = root.der().as_ref().to_vec();
        let mut exp = expected_pinning(root_der.clone());
        exp.now_unix = Some(1_700_000_000); // "now" is well before the leaf's not_before
        let chain: Vec<&[u8]> = vec![&leaf_der, &inter_der, &root_der];
        assert_eq!(
            verify_key_attestation(&chain, &exp),
            Verdict::Mismatch("certificate validity — a chain cert is expired or not yet valid")
        );
    }

    #[test]
    fn google_root_pin_provenance_urls_are_the_documented_endpoints() {
        // Regression guard: these two constants ARE the operator-facing fetch
        // procedure documented on GoogleRootPinProvenance — a typo here would
        // silently point an operator at the wrong endpoint.
        assert_eq!(
            GoogleRootPinProvenance::ROOT_LIST_URL,
            "https://android.googleapis.com/attestation/root"
        );
        assert_eq!(
            GoogleRootPinProvenance::STATUS_LIST_URL,
            "https://android.googleapis.com/attestation/status"
        );
    }

    #[test]
    fn root_fingerprint_is_stable_and_distinguishes_roots() {
        let kd = key_description(2, &[1, 2, 3, 4], true, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);
        let a = real_attested_chain(&kd);
        let b = real_attested_chain(&kd);
        let fp_a1 = root_fingerprint_sha256(&a.root);
        let fp_a2 = root_fingerprint_sha256(&a.root);
        let fp_b = root_fingerprint_sha256(&b.root);
        assert_eq!(fp_a1, fp_a2, "fingerprint must be deterministic");
        assert_ne!(fp_a1, fp_b, "distinct roots must not collide");
    }

    // ── negative-path COMPLETENESS (Dev D4 / bucket-B StrongBox coverage) ───
    // Every `Verdict::Mismatch` / `Verdict::Unverified` arm in this module gets
    // an explicit fail-closed negative here. All vectors are SYNTHETIC — hand-
    // built DER or an rcgen test chain — and no real StrongBox device produced
    // any of them (`vector-tested ≠ attested`, restated per module docs; the
    // hardware `attest()` path in StrongBoxAttestationGateway.kt stays
    // UNTESTED-until-VM/device and is labelled, never green-washed here).
    //
    // Coverage map of the arms NOT already exercised above:
    //   verify_key_attestation_detailed:
    //     - "invalid verifier clock"                    → invalid_verifier_clock_*
    //     - "no attestation extension"                  → leaf_without_attestation_extension_*
    //   evaluate:
    //     - "security level — unknown …SecurityLevel"   → unknown_security_level_*
    //     - "root of trust — no verifiedBootState …"    → missing_verified_boot_state_*
    //     - "root of trust — unknown verifiedBootState" → unknown_verified_boot_state_*
    //     - "root of trust — no deviceLocked …"         → missing_device_locked_*
    //     - "os patch level — not reported …"           → missing_os_patch_level_when_required_*
    //   parser arms (each surfaces as a named Verdict::Mismatch via map_err):
    //     - "…malformed DER"                            → truncated_der_*
    //     - "…integer out of range"                     → integer_out_of_range_*
    //     - "…KeyDescription is not a SEQUENCE"         → key_description_not_sequence_*
    //     - "…attestationChallenge is not an OCTET …"   → challenge_not_octet_string_*
    //     - "…AuthorizationList is not a SEQUENCE"      → authorization_list_not_sequence_*
    //     - "…RootOfTrust is not a SEQUENCE"            → root_of_trust_not_sequence_*
    //     - "…deviceLocked is not a BOOLEAN"            → device_locked_not_boolean_*
    //     - "…AttestationApplicationId is not an OCTET" → app_id_not_octet_string_*
    //     - "…AttestationApplicationId is not a SEQ …"  → app_id_not_sequence_*
    // (The remaining arms — Unverified no-root, empty chain, chain length,
    //  certificate parse, certificate validity, chain signature, issuer
    //  constraint, trust anchor, nonce, security-level floor, verified boot,
    //  device locked, os-patch floor, app package, app signing cert — already
    //  have dedicated negatives above.)

    #[test]
    fn invalid_verifier_clock_is_rejected_full_path() {
        // A verifier clock that is not a representable ASN.1 time must fail
        // closed rather than silently skip the validity window.
        let kd = key_description(2, &[1, 2, 3, 4], true, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);
        let c = real_attested_chain(&kd);
        let mut exp = expected_pinning(c.root.clone());
        exp.now_unix = Some(i64::MAX); // out of ASN1Time's representable range
        let chain: Vec<&[u8]> = vec![&c.leaf, &c.inter, &c.root];
        assert_eq!(
            verify_key_attestation(&chain, &exp),
            Verdict::Mismatch("invalid verifier clock")
        );
    }

    #[test]
    fn leaf_without_attestation_extension_is_rejected_full_path() {
        // A real, well-formed, correctly-anchored chain whose leaf carries NO
        // Android Key-Attestation extension: nothing to verify ⇒ fail closed.
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut rp = CertificateParams::new(vec!["Postern Test Attestation Root".into()]).unwrap();
        rp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        rp.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let root = rp.self_signed(&root_key).unwrap();

        let inter_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ip =
            CertificateParams::new(vec!["Postern Test Attestation Intermediate".into()]).unwrap();
        ip.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ip.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let inter = ip.signed_by(&inter_key, &root, &root_key).unwrap();

        // Leaf with NO custom Key-Attestation extension.
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let lp = CertificateParams::new(vec!["Android Keystore Attested Key".into()]).unwrap();
        let leaf = lp.signed_by(&leaf_key, &inter, &inter_key).unwrap();

        let leaf_der = leaf.der().as_ref().to_vec();
        let inter_der = inter.der().as_ref().to_vec();
        let root_der = root.der().as_ref().to_vec();
        let exp = expected_pinning(root_der.clone());
        let chain: Vec<&[u8]> = vec![&leaf_der, &inter_der, &root_der];
        assert_eq!(
            verify_key_attestation(&chain, &exp),
            Verdict::Mismatch("no attestation extension — leaf carries no Android Key-Attestation record")
        );
    }

    #[test]
    fn unknown_security_level_is_rejected() {
        // attestationSecurityLevel = 5 is not a defined KeyMint SecurityLevel;
        // an unrecognised tier must fail closed, never be treated as hardware.
        let der = key_description(5, &[1, 2, 3, 4], true, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);
        assert_eq!(
            parse_and_eval(&der, &base_expected()),
            Verdict::Mismatch("security level — unknown attestation SecurityLevel")
        );
    }

    #[test]
    fn missing_verified_boot_state_is_rejected() {
        // teeEnforced carries NO RootOfTrust ⇒ verifiedBootState absent. The
        // hardware-enforced boot posture is unknown ⇒ refuse.
        let software =
            sequence(&ctx(TAG_ATTESTATION_APPLICATION_ID, &octet(&app_id("labs.postern.wallet", &[0xAB; 32]))));
        let tee = sequence(&ctx(TAG_OS_PATCH_LEVEL, &int(202401)));
        let der = sequence(
            &[
                int(200),
                enumerated(2),
                int(4),
                enumerated(2),
                octet(&[1, 2, 3, 4]),
                octet(&[]),
                software,
                tee,
            ]
            .concat(),
        );
        assert_eq!(
            parse_and_eval(&der, &base_expected()),
            Verdict::Mismatch("root of trust — no verifiedBootState in the hardware-enforced list")
        );
    }

    #[test]
    fn unknown_verified_boot_state_is_rejected() {
        // verifiedBootState = 7 is outside the defined enum {0..3}: an
        // unrecognised boot state must fail closed, not be waved through.
        let der = key_description(2, &[1, 2, 3, 4], true, 7, 202401, "labs.postern.wallet", &[0xAB; 32]);
        assert_eq!(
            parse_and_eval(&der, &base_expected()),
            Verdict::Mismatch("root of trust — unknown verifiedBootState")
        );
    }

    #[test]
    fn missing_device_locked_is_rejected() {
        // The parser always reads deviceLocked and verifiedBootState together
        // from one RootOfTrust SEQUENCE, so a wire vector can't present one
        // without the other. This synthetic KeyDescription (built directly, not
        // from DER) isolates the `deviceLocked == None` arm: verifiedBootState
        // is present and Verified, but deviceLocked is absent ⇒ fail closed.
        let kd = KeyDescription {
            attestation_security_level: 2,
            challenge: vec![1, 2, 3, 4],
            device_locked: None,
            verified_boot_state: Some(0), // Verified — so the vb check passes first
            os_patch_level: Some(202401),
            package_names: vec!["labs.postern.wallet".into()],
            signature_digests: vec![vec![0xAB; 32]],
        };
        assert_eq!(
            evaluate(&kd, &base_expected()).unwrap_err(),
            Verdict::Mismatch("root of trust — no deviceLocked in the hardware-enforced list")
        );
    }

    #[test]
    fn missing_os_patch_level_when_required_is_rejected() {
        // teeEnforced carries a RootOfTrust but NO osPatchLevel, while the
        // policy requires a minimum ⇒ anti-rollback cannot be evaluated ⇒ refuse.
        let software =
            sequence(&ctx(TAG_ATTESTATION_APPLICATION_ID, &octet(&app_id("labs.postern.wallet", &[0xAB; 32]))));
        let tee = sequence(&ctx(TAG_ROOT_OF_TRUST, &root_of_trust(true, 0)));
        let der = sequence(
            &[
                int(200),
                enumerated(2),
                int(4),
                enumerated(2),
                octet(&[1, 2, 3, 4]),
                octet(&[]),
                software,
                tee,
            ]
            .concat(),
        );
        assert_eq!(
            parse_and_eval(&der, &base_expected()),
            Verdict::Mismatch("os patch level — not reported but a minimum is required")
        );
    }

    #[test]
    fn truncated_der_is_rejected() {
        // A TLV whose declared length overruns its content: the parser's
        // `take` must reject rather than read out of bounds.
        assert_eq!(
            parse_key_description(&[0x30, 0x05, 0x01]).unwrap_err(),
            "attestation extension — malformed DER"
        );
    }

    #[test]
    fn integer_out_of_range_is_rejected() {
        // A 9-byte ENUMERATED for attestationSecurityLevel exceeds the u64 cap
        // `as_uint` enforces ⇒ reject (guards against a huge/negative field).
        let der = sequence(
            &[
                int(200),
                tlv(0x0A, &[0x01; 9]), // 9-byte ENUMERATED — out of range
                int(4),
                enumerated(2),
                octet(&[1, 2, 3, 4]),
                octet(&[]),
                sequence(&[]),
                sequence(&[]),
            ]
            .concat(),
        );
        assert_eq!(
            parse_and_eval(&der, &base_expected()),
            Verdict::Mismatch("attestation extension — integer out of range")
        );
    }

    #[test]
    fn key_description_not_sequence_exact_message() {
        // Top-level KeyDescription that is an OCTET STRING, not a SEQUENCE.
        assert_eq!(
            parse_key_description(&octet(&[1, 2, 3])).unwrap_err(),
            "attestation extension — KeyDescription is not a SEQUENCE"
        );
    }

    #[test]
    fn challenge_not_octet_string_is_rejected() {
        // Field 4 (attestationChallenge) presented as an INTEGER, not an OCTET
        // STRING ⇒ reject (a mistyped nonce must never be silently accepted).
        let der = sequence(
            &[
                int(200),
                enumerated(2),
                int(4),
                enumerated(2),
                int(7), // challenge slot — WRONG type
                octet(&[]),
                sequence(&[]),
                sequence(&[]),
            ]
            .concat(),
        );
        assert_eq!(
            parse_and_eval(&der, &base_expected()),
            Verdict::Mismatch("attestation extension — attestationChallenge is not an OCTET STRING")
        );
    }

    #[test]
    fn authorization_list_not_sequence_is_rejected() {
        // softwareEnforced presented as an OCTET STRING, not an AuthorizationList
        // SEQUENCE ⇒ reject.
        let der = sequence(
            &[
                int(200),
                enumerated(2),
                int(4),
                enumerated(2),
                octet(&[1, 2, 3, 4]),
                octet(&[]),
                octet(&[1, 2]), // softwareEnforced — not a SEQUENCE
                sequence(&[]),
            ]
            .concat(),
        );
        assert_eq!(
            parse_and_eval(&der, &base_expected()),
            Verdict::Mismatch("attestation extension — AuthorizationList is not a SEQUENCE")
        );
    }

    #[test]
    fn root_of_trust_not_sequence_is_rejected() {
        // The [704] RootOfTrust wrapper contains an OCTET STRING, not a SEQUENCE.
        let software =
            sequence(&ctx(TAG_ATTESTATION_APPLICATION_ID, &octet(&app_id("labs.postern.wallet", &[0xAB; 32]))));
        let tee = sequence(&ctx(TAG_ROOT_OF_TRUST, &octet(&[1, 2, 3])));
        let der = sequence(
            &[
                int(200),
                enumerated(2),
                int(4),
                enumerated(2),
                octet(&[1, 2, 3, 4]),
                octet(&[]),
                software,
                tee,
            ]
            .concat(),
        );
        assert_eq!(
            parse_and_eval(&der, &base_expected()),
            Verdict::Mismatch("attestation extension — RootOfTrust is not a SEQUENCE")
        );
    }

    #[test]
    fn device_locked_not_boolean_is_rejected() {
        // Inside RootOfTrust, deviceLocked presented as an INTEGER, not a
        // BOOLEAN ⇒ reject (a mistyped lock state must not be coerced true).
        let bad_rot = sequence(
            &[
                octet(&[0u8; 32]),
                int(1), // deviceLocked slot — WRONG type
                enumerated(0),
                octet(&[0u8; 32]),
            ]
            .concat(),
        );
        let software =
            sequence(&ctx(TAG_ATTESTATION_APPLICATION_ID, &octet(&app_id("labs.postern.wallet", &[0xAB; 32]))));
        let tee = sequence(&ctx(TAG_ROOT_OF_TRUST, &bad_rot));
        let der = sequence(
            &[
                int(200),
                enumerated(2),
                int(4),
                enumerated(2),
                octet(&[1, 2, 3, 4]),
                octet(&[]),
                software,
                tee,
            ]
            .concat(),
        );
        assert_eq!(
            parse_and_eval(&der, &base_expected()),
            Verdict::Mismatch("attestation extension — deviceLocked is not a BOOLEAN")
        );
    }

    #[test]
    fn app_id_not_octet_string_is_rejected() {
        // The [709] AttestationApplicationId wrapper carries an INTEGER, not the
        // required OCTET STRING ⇒ reject.
        let software = sequence(&ctx(TAG_ATTESTATION_APPLICATION_ID, &int(5)));
        let tee = sequence(&ctx(TAG_ROOT_OF_TRUST, &root_of_trust(true, 0)));
        let der = sequence(
            &[
                int(200),
                enumerated(2),
                int(4),
                enumerated(2),
                octet(&[1, 2, 3, 4]),
                octet(&[]),
                software,
                tee,
            ]
            .concat(),
        );
        assert_eq!(
            parse_and_eval(&der, &base_expected()),
            Verdict::Mismatch("attestation extension — AttestationApplicationId is not an OCTET STRING")
        );
    }

    #[test]
    fn app_id_not_sequence_is_rejected() {
        // The OCTET STRING inside [709] wraps content that is an INTEGER, not
        // the required AttestationApplicationId SEQUENCE ⇒ reject.
        let software = sequence(&ctx(TAG_ATTESTATION_APPLICATION_ID, &octet(&int(5))));
        let tee = sequence(&ctx(TAG_ROOT_OF_TRUST, &root_of_trust(true, 0)));
        let der = sequence(
            &[
                int(200),
                enumerated(2),
                int(4),
                enumerated(2),
                octet(&[1, 2, 3, 4]),
                octet(&[]),
                software,
                tee,
            ]
            .concat(),
        );
        assert_eq!(
            parse_and_eval(&der, &base_expected()),
            Verdict::Mismatch("attestation extension — AttestationApplicationId is not a SEQUENCE")
        );
    }

    // ── tier "never upgrade" pure invariant (Dev D4, PARTITION P2) ──────────

    #[test]
    fn reported_tier_is_never_upgraded_past_what_the_chain_attests() {
        // The honest-tier rule: the reported SecurityLevel equals EXACTLY what
        // the attestation claims, never re-labelled upward. A TEE-attested key
        // accepted under a TEE floor must report TrustedEnvironment — never get
        // silently promoted to StrongBox (the fallback-tier trap the device
        // gateway's "report TEE, never re-label as STRONGBOX" rule guards).
        let mut exp = base_expected();
        exp.min_security_level = SecurityLevel::TrustedEnvironment;

        let tee_der = key_description(1, &[1, 2, 3, 4], true, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);
        let kd_tee = parse_key_description(&tee_der).unwrap();
        let att_tee = evaluate(&kd_tee, &exp).unwrap();
        assert_eq!(att_tee.security_level, SecurityLevel::TrustedEnvironment);
        assert_ne!(att_tee.security_level, SecurityLevel::StrongBox);

        // And a StrongBox-attested key reports StrongBox: the label tracks the
        // evidence in BOTH directions, never fixed high or low.
        let sb_der = key_description(2, &[1, 2, 3, 4], true, 0, 202401, "labs.postern.wallet", &[0xAB; 32]);
        let kd_sb = parse_key_description(&sb_der).unwrap();
        let att_sb = evaluate(&kd_sb, &exp).unwrap();
        assert_eq!(att_sb.security_level, SecurityLevel::StrongBox);
    }

    // ── golden-DER wire-contract fixture (Dev D4, PARTITION P2) ─────────────

    #[test]
    fn golden_der_wire_fixture_locks_the_a_to_c_contract() {
        // A deterministic, checked-in SYNTHETIC KeyDescription extension payload
        // + nonce (NO real StrongBox produced it — `vector-tested ≠ attested`).
        // It pins the exact leaf-first DER + nonce wire the Kotlin
        // `AttestationEvidence` (side A) must emit for `verify_key_attestation`
        // (side C) to keep consuming it. A drift in either the encoder OR the
        // positional field layout trips this fixture.
        const GOLDEN_NONCE: [u8; 4] = [0xA1, 0xB2, 0xC3, 0xD4];
        const GOLDEN_DIGEST: [u8; 32] = [0x11; 32];
        #[rustfmt::skip]
        const GOLDEN_KD_DER: &[u8] = &[
            0x30, 0x81, 0xBA, 0x02, 0x02, 0x00, 0xC8, 0x0A, 0x01, 0x02, 0x02, 0x01, 0x04, 0x0A, 0x01, 0x02,
            0x04, 0x04, 0xA1, 0xB2, 0xC3, 0xD4, 0x04, 0x00, 0x30, 0x48, 0xBF, 0x85, 0x45, 0x44, 0x04, 0x42,
            0x30, 0x40, 0x31, 0x1A, 0x30, 0x18, 0x04, 0x13, 0x6C, 0x61, 0x62, 0x73, 0x2E, 0x70, 0x6F, 0x73,
            0x74, 0x65, 0x72, 0x6E, 0x2E, 0x77, 0x61, 0x6C, 0x6C, 0x65, 0x74, 0x02, 0x01, 0x01, 0x31, 0x22,
            0x04, 0x20, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x30, 0x59, 0xBF, 0x85, 0x40, 0x4C, 0x30, 0x4A, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xFF, 0x0A,
            0x01, 0x00, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xBF, 0x85, 0x42, 0x05, 0x02, 0x03, 0x03, 0x16, 0xA1,
        ];

        // 1. The encoder output is pinned byte-for-byte to the golden vector.
        let built =
            key_description(2, &GOLDEN_NONCE, true, 0, 202401, "labs.postern.wallet", &GOLDEN_DIGEST);
        assert_eq!(
            built.as_slice(),
            GOLDEN_KD_DER,
            "KeyDescription wire encoding drifted from the golden fixture"
        );

        // 2. The parser reads back EXACTLY the fields the golden wire carries.
        let kd = parse_key_description(GOLDEN_KD_DER).unwrap();
        assert_eq!(kd.challenge, GOLDEN_NONCE);
        assert_eq!(kd.attestation_security_level, 2);
        assert_eq!(kd.verified_boot_state, Some(0));
        assert_eq!(kd.device_locked, Some(true));
        assert_eq!(kd.os_patch_level, Some(202401));
        assert_eq!(kd.package_names, vec!["labs.postern.wallet".to_string()]);
        assert_eq!(kd.signature_digests, vec![GOLDEN_DIGEST.to_vec()]);

        // 3. Full A↔C path: the golden payload embedded in a real leaf-first
        //    chain, bound to the golden nonce, verifies Genuine end to end.
        let c = real_attested_chain(GOLDEN_KD_DER);
        let mut exp = expected_pinning(c.root.clone());
        exp.challenge = GOLDEN_NONCE.to_vec();
        exp.expected_app = Some(AppIdentity {
            package_names: vec!["labs.postern.wallet".into()],
            signature_digests: vec![GOLDEN_DIGEST.to_vec()],
        });
        let chain: Vec<&[u8]> = vec![&c.leaf, &c.inter, &c.root];
        assert_eq!(verify_key_attestation(&chain, &exp), Verdict::Genuine);
    }
}

// ── REAL captured-emulator vectors (feature `mobile-attest`) ────────────────
//
// Every chain in the `tests` module above is built with `rcgen` (SYNTHETIC).
// This module is the first vector set emitted by a **real Android Keystore /
// KeyMint**: an EC P-256 key generated in `AndroidKeyStore` via
// `KeyGenParameterSpec.setAttestationChallenge(nonce)` on a booted API-34
// `google_apis;x86_64` emulator (the TEE / `setIsStrongBoxBacked(false)` path,
// exactly what `StrongBoxKey.generateTeeFallbackKey` drives on hardware). The
// leaf-first DER chain the Keystore returned is committed verbatim under
// `testdata/` (provenance + capture harness described in `testdata/PROVENANCE.md`).
//
// These tests run the FULL parse+evaluate pipeline —
// `verify_key_attestation_detailed` — over that real chain and assert NAMED,
// honest [`Verdict`]s. What the emulator actually attests (decoded from the real
// Key-Attestation extension) is the honest, load-bearing fact here:
//
//   * `attestationSecurityLevel = Software` (0) — the `google_apis` emulator's
//     KeyMint is a **software** reference implementation, NOT a real TEE. The
//     captured chain anchors to the AOSP `CN=Android Keystore Software
//     Attestation Root` (`O=Google, Inc.`) via its `…Software Attestation
//     Intermediate` — a *software* attestation root, NOT a Google *production*
//     hardware-attestation root; the attested security level is Software.
//   * the `teeEnforced` authorization list is **EMPTY** — the RootOfTrust
//     lives only in `softwareEnforced`, which this hardened verifier
//     deliberately does not trust for boot state.
//
// So an honest `Verdict::Genuine` at TEE tier is IMPOSSIBLE against this
// emulator (it genuinely is not hardware-backed) — asserting one would be a lie.
// The truthful, named outcomes below instead prove the real chain flows through
// every stage (DER parse → validity window → issuer signature linkage → CA
// constraints → trust-anchor pinning → attestation-extension parse →
// KeyDescription field evaluation) and fails **closed** exactly where it
// should. `captured ≠ StrongBox-hardware-attested`. UNAUDITED, no security claim.
#[cfg(test)]
mod captured_emulator_attestation {
    use super::*;

    // Leaf-first, exactly as the emulator KeyStore returned it.
    const LEAF: &[u8] = include_bytes!("testdata/chain-0.der");
    const INTER: &[u8] = include_bytes!("testdata/chain-1.der");
    const ROOT: &[u8] = include_bytes!("testdata/chain-2.der");
    const NONCE: &[u8] = include_bytes!("testdata/nonce.bin");
    // A genuine Google *production* hardware-attestation root (serial
    // f92009e853b6b045; its RSA-4096 key == Google's published
    // GOOGLE_ROOT_CA_PUB_KEY) — the emulator chain must NOT anchor to this.
    const GOOGLE_PROD_ROOT: &[u8] = include_bytes!("testdata/google_prod_attestation_root.der");

    // Fixed verifier clock (2020-06-01 00:00:00 UTC) inside every captured
    // cert's validity window (leaf 1970..2048; AOSP software-attestation
    // intermediate 2016-01-11..2026-01-08; root 2016-01-11..2036-01-06) —
    // deterministic even after the intermediate's 2026-01-08 wall-clock expiry.
    // See PROVENANCE.md.
    const CAPTURE_CLOCK_UNIX: i64 = 1_590_969_600;

    fn chain() -> Vec<&'static [u8]> {
        vec![LEAF, INTER, ROOT]
    }

    /// Base policy pinned to the emulator's OWN captured root, at the honest
    /// Software floor and permissive boot flags — so parse+anchor+nonce all
    /// pass and the pipeline reaches the field-evaluation stage.
    fn expected_pinned_to_emulator_root() -> MobileExpected {
        MobileExpected {
            roots: vec![ROOT.to_vec()],
            challenge: NONCE.to_vec(),
            require_device_locked: false,
            require_verified_boot: false,
            min_security_level: SecurityLevel::Software,
            min_os_patch_level: None,
            expected_app: None,
            now_unix: Some(CAPTURE_CLOCK_UNIX),
        }
    }

    /// Acceptance option (b): the real Keystore chain, run through the full
    /// parse pipeline, does NOT terminate at a pinned **Google production**
    /// attestation root — an honest, named `Verdict::Mismatch("trust anchor …")`,
    /// never a false Genuine. Reaching the anchor step (step 4) proves the real
    /// DER parse, validity-window, issuer-signature-linkage and CA-constraint
    /// stages (1–3b) all PASSED on the captured chain.
    #[test]
    fn real_chain_is_mismatch_against_pinned_google_prod_root() {
        let mut exp = expected_pinned_to_emulator_root();
        exp.roots = vec![GOOGLE_PROD_ROOT.to_vec()];
        match verify_key_attestation_detailed(&chain(), &exp) {
            Err(Verdict::Mismatch(reason)) => assert!(
                reason.contains("trust anchor"),
                "expected a trust-anchor mismatch, got: {reason}"
            ),
            other => panic!("expected Mismatch(trust anchor …), got {other:?}"),
        }
    }

    /// The captured chain anchors to its own emulator root and its embedded
    /// `attestationChallenge` really is our nonce: pass the WRONG nonce and the
    /// evaluator returns the named nonce `Mismatch`. Reaching the nonce check
    /// (inside `evaluate`) proves anchor + attestation-extension parse both ran
    /// over the real chain and that the leaf carried our exact challenge.
    #[test]
    fn real_chain_binds_the_capture_nonce() {
        // Sanity: the honest floor policy passes the nonce check (it fails
        // later, on the missing hardware-enforced boot state — see below).
        let ok_nonce = expected_pinned_to_emulator_root();
        assert!(matches!(
            verify_key_attestation_detailed(&chain(), &ok_nonce),
            Err(Verdict::Mismatch(r)) if r.contains("root of trust")
        ));

        let mut wrong = expected_pinned_to_emulator_root();
        wrong.challenge = b"not-the-nonce-the-keystore-signed".to_vec();
        match verify_key_attestation_detailed(&chain(), &wrong) {
            Err(Verdict::Mismatch(reason)) => {
                assert!(reason.contains("nonce"), "expected nonce mismatch, got: {reason}")
            }
            other => panic!("expected Mismatch(nonce …), got {other:?}"),
        }
    }

    /// The captured chain attests at **Software** tier, not hardware: require a
    /// StrongBox floor and the evaluator returns the named security-level
    /// `Mismatch`. This is the honest ceiling of an emulator attestation — it is
    /// below any real hardware tier.
    #[test]
    fn real_chain_is_below_the_strongbox_tier() {
        let mut exp = expected_pinned_to_emulator_root();
        exp.min_security_level = SecurityLevel::StrongBox;
        match verify_key_attestation_detailed(&chain(), &exp) {
            Err(Verdict::Mismatch(reason)) => assert!(
                reason.contains("security level"),
                "expected security-level mismatch, got: {reason}"
            ),
            other => panic!("expected Mismatch(security level …), got {other:?}"),
        }
    }

    /// Deepest stage: even pinned to its own root, at the Software floor, with
    /// the correct nonce, the real chain fails **closed** because the emulator's
    /// KeyMint left the `teeEnforced` list empty — there is no HARDWARE-enforced
    /// verifiedBootState to trust. This is the load-bearing honest result: a
    /// software-level emulator attestation is not accepted as a hardware root of
    /// trust. Reaching this verdict proves the KeyDescription parse + field
    /// evaluation ran end-to-end over the real chain.
    #[test]
    fn real_chain_has_no_hardware_enforced_root_of_trust() {
        let exp = expected_pinned_to_emulator_root();
        match verify_key_attestation_detailed(&chain(), &exp) {
            Err(Verdict::Mismatch(reason)) => assert!(
                reason.contains("root of trust") && reason.contains("verifiedBootState"),
                "expected missing hardware-enforced verifiedBootState, got: {reason}"
            ),
            other => panic!("expected Mismatch(root of trust …), got {other:?}"),
        }
        // The thin wrapper returns the same named verdict.
        assert!(matches!(
            verify_key_attestation(&chain(), &exp),
            Verdict::Mismatch(r) if r.contains("root of trust")
        ));
    }

    /// POSITIVE decode over the REAL captured leaf.
    ///
    /// Every other test in this module proves the parser ran only *indirectly*,
    /// via negative floors: it reaches a named `Mismatch` at the nonce, the
    /// security-level, or the root-of-trust stage, so the ASN.1 pipeline must
    /// have decoded *something*. This test instead pulls the real KeyMint
    /// `KEY_ATTESTATION_OID` extension out of the captured leaf, runs the same
    /// `parse_key_description` the verifier uses, and asserts the DECODED field
    /// values EQUAL the ground truth of the capture:
    ///
    ///   * `attestationSecurityLevel == 0` — `SecurityLevel::Software`, the
    ///     `google_apis` emulator's software KeyMint (NOT a TEE / StrongBox).
    ///   * `attestationChallenge == nonce.bin`, byte-for-byte — the exact
    ///     challenge the Java `KeyGenParameterSpec` set on the captured key.
    ///
    /// Because these bytes were emitted by real KeyMint (not an `rcgen`-built
    /// synthetic vector), a green assertion here proves the parser reads genuine
    /// Android Keystore output, not just self-authored test fixtures.
    /// `captured != StrongBox-attested`; UNAUDITED, no hardware security claim.
    #[test]
    fn real_leaf_decodes_to_software_level_and_the_capture_nonce() {
        // Parse the captured leaf exactly as `verify_key_attestation_detailed`
        // (step 1) does, then locate the Android Key-Attestation extension.
        let (rest, leaf) = X509Certificate::from_der(LEAF)
            .expect("captured leaf must be well-formed DER");
        assert!(rest.is_empty(), "captured leaf DER had trailing bytes");

        let ext = leaf
            .extensions()
            .iter()
            .find(|e| e.oid.as_bytes() == KEY_ATTESTATION_OID)
            .expect("captured leaf must carry the KEY_ATTESTATION_OID extension");

        // Same decode path the verifier uses (step 5).
        let kd = parse_key_description(ext.value)
            .expect("real KeyMint KeyDescription must parse");

        // (1) attestationSecurityLevel is the raw ENUMERATED 0 == Software.
        assert_eq!(
            kd.attestation_security_level, 0,
            "captured emulator KeyMint attests at Software(0), not a hardware tier",
        );
        assert_eq!(
            SecurityLevel::from_enum(kd.attestation_security_level),
            Some(SecurityLevel::Software),
            "decoded security level must map to SecurityLevel::Software",
        );

        // (2) attestationChallenge is our vendored nonce, byte-for-byte.
        assert_eq!(
            kd.challenge.as_slice(),
            NONCE,
            "decoded attestationChallenge must equal nonce.bin exactly",
        );
    }
}
