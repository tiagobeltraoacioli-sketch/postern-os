// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs

//! Intel TDX — the documented SECONDARY TEE (POSTERN-CLOUD.md; SEV-SNP is
//! primary). This module is an honest **fail-closed** verifier: it now does the
//! parts that need no trust root — parse a real TD quote, extract the measured
//! fields (`MRTD`/`MRCONFIGID`/`RTMR[0..4]`/`report_data`), and compare them to
//! the caller's expected values — but the final verdict is STILL never
//! `Genuine`, because the one load-bearing step, verifying the quote's
//! signature up the Intel PCS/DCAP chain to the pinned Intel SGX Root CA, is
//! not implemented. **A verifier that cannot check the chain must never say
//! Genuine** (mirrors [`crate::snp`]'s authenticate-then-compare order: here the
//! authenticate step is a hard, unconditional close).
//!
//! What is REAL here (needs no hardware, tested in the default build):
//!   • [`parse_td_quote`] — a structural decoder for a DCAP **v4** TD quote
//!     (SGX quote-4 header + TDX 1.0 report body), with strict length/type/
//!     version checks and no allocation before bounds are proven. It does NOT
//!     authenticate anything; a forged quote parses fine and is rejected at the
//!     chain gate.
//!   • [`check_bound_fields`] — the field comparison a real verifier runs
//!     AFTER the chain checks out: `MRTD` (the SNP `measurement` analogue),
//!     `MRCONFIGID` (the `HOSTDATA` analogue), the 64-byte `report_data`
//!     channel binding ([`crate::binding`] — layout shared with SNP), and the
//!     runtime `RTMR` measured-boot registers when pinned.
//!
//! The fail-closed gate ([`verify_collateral`], no-collateral overload) still
//! returns `Err` unconditionally, so [`verify_td_quote`] (which has no
//! collateral to pass) can only ever return [`crate::Verdict::Unverified`].
//!
//! What IS now implemented, behind feature `tdx-verify` (a `dcap-qvl`-style
//! pure-Rust path — [`verify_collateral_dcap`] / [`verify_td_quote_with_collateral`]):
//!   1. parse the DCAP **v4** ECDSA signature section (quote signature,
//!      attestation key, QE report + its signature, QE auth data, and the
//!      embedded PCK cert chain);
//!   2. verify the quote-signing chain PCK → Intel SGX processor CA →
//!      **pinned Intel SGX Root CA** (`x509-parser`/ring), the chain being
//!      anchored by DER-equality to the pinned root — never taken from the wire;
//!   3. PCK leaf/intermediate/root **X.509 validity windows**
//!      (`notBefore`/`notAfter`) at the caller-supplied `now_unix`, mirroring
//!      [`crate::mobile`]'s `certificate validity` check — independent of, and
//!      in addition to, CRL freshness (a fresh CRL says nothing about whether
//!      the certs themselves are still inside their own validity window);
//!   4. CRL freshness + revocation for the Intel Root/PCK CAs (`nextUpdate`
//!      not elapsed, serial not revoked);
//!   5. the QE-report binding `SHA-256(att_pub_key ‖ qe_auth) == qe_report_data`,
//!      the QE-report signature under the PCK, and the quote signature under the
//!      attestation key (raw P-256 ECDSA, `p256`);
//!   6. an anti-rollback TCB-SVN floor on the TD report's `TEE_TCB_SVN`.
//!
//! HONEST LIMITS, still true here (the rails):
//!   • The pinned Intel SGX Root CA ([`PINNED_INTEL_SGX_ROOT_CA_DER`]) is now
//!     populated with Intel's genuine, published root DER, so the PCK →
//!     processor CA → root chain can finally be *anchored*. This is necessary,
//!     not sufficient: pinning the anchor authenticates the chain — it does NOT
//!     mean a real TDX quote was verified. Reaching `Genuine` still needs a
//!     genuine Intel TDX quote + matching PCS/DCAP collateral from silicon we
//!     launched (**hardware-gated**); this code has NEVER been run against a
//!     quote from TEE hardware we control. The REAL crypto is exercised in tests
//!     against a SYNTHETIC anchor root ([`verify_collateral_anchored`]) — the
//!     pinned-root tests only prove the anchor parses and that a synthetic
//!     (non-Intel-rooted) quote now reaches `RootNotAnchored`, not
//!     `PinnedRootUnset`. UNAUDITED.
//!   • Intel TCB-info / QE-identity JSON collateral verification IS now folded in
//!     (feature `tdx-verify`, [`TdxCollateral::json`]): the Intel TCB **signing
//!     cert** chain to the same anchored Intel root, both JSON **signatures** over
//!     their raw signed bodies, `nextUpdate` **freshness**, the matched TCB
//!     **status** (strict: only `UpToDate` passes), and the **cross-checks**
//!     against the quote/PCK — FMSPC + the SGX/TDX TCB components that select the
//!     level, plus the QE report's identity (mrsigner/isvprodid/masked
//!     miscselect+attributes) and ISV-SVN level. Still fail-closed and, on this
//!     host, never `Genuine` (our synthetic quotes chain to a test root, not
//!     Intel's). When [`TdxCollateral::json`] is `None` the JSON checks are
//!     consciously waived (documented, exactly like a `None` CRL) — the
//!     chain/CRL/QE-binding/signature checks still run. UNAUDITED against real
//!     Intel silicon; see [`tests/tdx_collateral.rs`] for the offline vectors
//!     proving each JSON check bites.
//!
//! ## RESOLVED: the fail-closed-default / real-DCAP-path split is PERMANENT API
//!
//! `docs/bucketB/PARTITION.md` flagged an open design question for this module:
//! should `tdx-verify` change what [`verify_td_quote`]/[`verify_td_quote_bound`]
//! DO (i.e. make the same function names become the real chain check once the
//! feature is compiled in), or should the two-entry-point split — fail-closed
//! stub vs. real DCAP path, under separate, differently-named functions — stay
//! permanent? **Decision: the split stays permanent.** Reasoning:
//!
//!   1. **Feature-gated behavior change of an already-public, already-named
//!      function is a caller-invisible footgun.** If `verify_td_quote_bound`'s
//!      MEANING depended on whether some *other* crate in the dependency graph
//!      turned on `tdx-verify` (Cargo features are additive/global across a
//!      build), the exact same call site — same import, same signature, same
//!      call — would silently start returning `Genuine` for some builds and
//!      `Unverified` for others, with no diff in the calling code and no
//!      compiler signal. A caller reading `verify_td_quote_bound(quote, ...)` at
//!      the call site cannot tell which behavior they get without inspecting
//!      the whole workspace's feature unification. That is exactly the kind of
//!      "looks the same, means something different" gap this crate's entire
//!      honesty discipline exists to prevent (see [`crate::snp`]'s
//!      authenticate-then-compare framing, which this module mirrors).
//!   2. **Distinct names are a stronger safety property than a doc comment.**
//!      `verify_td_quote` / `verify_td_quote_bound` (no collateral parameter —
//!      cannot ever be `Genuine`, by construction of their signature) vs.
//!      `verify_td_quote_with_collateral` (collateral is a REQUIRED parameter —
//!      the only way to reach the real chain check) means a caller who has no
//!      `TdxCollateral` in hand literally cannot call the real path by
//!      accident, and a caller who DOES have collateral has to actively choose
//!      to ignore it to call the stub. The function signature itself, not just
//!      prose, enforces "you cannot reach for the wrong one without noticing."
//!   3. **A single merged function would need a fallback behavior for
//!      "compiled with `tdx-verify` but no collateral was supplied,"** which
//!      re-introduces exactly the ambiguity item 1 describes — should it
//!      silently accept `None` and fail closed (fine, but then why merge the
//!      functions at all — the behavior split still exists, just hidden inside
//!      one function instead of visible across two), or panic (a footgun of its
//!      own for a library function)? The two-name split sidesteps the question
//!      entirely by making "do you have collateral" part of the function you
//!      pick, not a runtime branch inside one function.
//!
//! This mirrors, and does not contradict, [`crate::snp`]'s single-entry-point
//! shape: SNP has ONE real verifier because SNP's hardware root (AMD ARK/ASK)
//! is compiled in unconditionally and there is no "stub vs. real" split to
//! begin with. TDX's split exists ONLY because the real DCAP path is
//! `tdx-verify`-feature-gated AND still unaudited against real hardware — once
//! it has run against real Intel-rooted quotes and the feature gate is judged
//! safe to remove, revisit this decision; until then, the naming split is the
//! load-bearing safety mechanism, not a temporary wart. Any future PR that
//! proposes making `verify_td_quote_bound` feature-aware should link back to
//! this note and explain what changed that invalidates reasoning above.

use crate::binding;

// ── DCAP v4 TD-quote layout constants (Intel `sgx_quote_4.h`) ────────────────

/// `tee_type` value marking a TDX quote (SGX is `0x0`).
const TEE_TYPE_TDX: u32 = 0x0000_0081;
/// The only quote version this decoder accepts.
const QUOTE_VERSION_V4: u16 = 4;
/// `sgx_quote4_header_t` is 48 bytes.
const HEADER_LEN: usize = 48;
/// TDX **1.0** report body (`sgx_report2_body_t`) is 584 bytes. TDX 1.5 adds
/// `MRSERVICETD` + a second TCB SVN (648 bytes); it is not decoded here (a
/// 1.5 body length fails the strict check below rather than being mis-parsed).
const TD_BODY_LEN: usize = 584;
/// Minimum bytes to read header + TD body (the signature section follows and
/// is only consumed by the — unimplemented — chain verification).
const MIN_QUOTE_LEN: usize = HEADER_LEN + TD_BODY_LEN;

// Header field offsets.
const OFF_VERSION: usize = 0;
const OFF_TEE_TYPE: usize = 4;

// TD-body field offsets, RELATIVE to the start of the body (i.e. + HEADER_LEN
// for an absolute offset into the quote). From `sgx_report2_body_t`.
const B_MRTD: usize = 136;
const B_MRCONFIGID: usize = 184;
const B_RTMR0: usize = 328;
const B_REPORTDATA: usize = 520;
const MR_LEN: usize = 48;
const RTMR_COUNT: usize = 4;

/// Expected values for a genuine TDX guest (the SNP-analogue of
/// [`crate::snp::SnpExpected`], minus the trust anchor — the anchor is the
/// pinned Intel root, once the chain check exists).
#[derive(Debug, Clone)]
pub struct TdxExpected {
    /// Build-time TD measurement (SHA-384), the SNP `measurement` analogue.
    pub mrtd: [u8; 48],
    /// Launch-config binding (the `HOSTDATA` analogue). `None` waives the check
    /// (document per deployment, exactly as [`crate::snp::SnpExpected::host_data`]).
    pub mr_config_id: Option<[u8; 48]>,
    /// Runtime measured-boot registers `RTMR[0..4]`, when pinned. `None` waives.
    pub rtmr: Option<[[u8; 48]; 4]>,
    /// Freshness + channel binding, `binding::report_data(nonce, guest_pubkey)`.
    pub report_data: [u8; 64],
}

/// The structurally-decoded, **UNAUTHENTICATED** fields of a TD quote. Holding
/// one proves only that the bytes were well-formed — never that any TEE
/// produced them. Authentication is [`verify_collateral`]'s (unimplemented) job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdQuoteBody {
    /// Quote version (must be [`QUOTE_VERSION_V4`]).
    pub version: u16,
    /// TEE type (must be [`TEE_TYPE_TDX`]).
    pub tee_type: u32,
    /// TD build measurement.
    pub mrtd: [u8; 48],
    /// TD launch-config measurement.
    pub mr_config_id: [u8; 48],
    /// Runtime measured-boot registers.
    pub rtmr: [[u8; 48]; 4],
    /// 64-byte report data (the channel-binding field).
    pub report_data: [u8; 64],
}

/// Why a TD quote could not be decoded. Named, for an honest UI line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TdParseError {
    /// Shorter than a header + a full TD 1.0 report body.
    TooShort,
    /// `version` field is not 4.
    UnsupportedVersion(u16),
    /// `tee_type` field is not TDX (e.g. a plain SGX quote).
    NotTdx(u32),
}

impl core::fmt::Display for TdParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TdParseError::TooShort => write!(f, "quote too short for a v4 TD 1.0 report body"),
            TdParseError::UnsupportedVersion(v) => write!(f, "unsupported quote version {v} (want 4)"),
            TdParseError::NotTdx(t) => write!(f, "tee_type 0x{t:08x} is not TDX (0x81)"),
        }
    }
}

fn le_u16(buf: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([buf[at], buf[at + 1]])
}
fn le_u32(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}
fn arr48(buf: &[u8], at: usize) -> [u8; 48] {
    let mut out = [0u8; 48];
    out.copy_from_slice(&buf[at..at + 48]);
    out
}

/// Structurally decode a DCAP v4 TD quote's header + TD 1.0 report body. Bounds
/// are checked before any read; nothing is authenticated. Fails closed on a
/// short buffer, a non-v4 version, or a non-TDX `tee_type`.
pub fn parse_td_quote(quote: &[u8]) -> Result<TdQuoteBody, TdParseError> {
    if quote.len() < MIN_QUOTE_LEN {
        return Err(TdParseError::TooShort);
    }
    let version = le_u16(quote, OFF_VERSION);
    if version != QUOTE_VERSION_V4 {
        return Err(TdParseError::UnsupportedVersion(version));
    }
    let tee_type = le_u32(quote, OFF_TEE_TYPE);
    if tee_type != TEE_TYPE_TDX {
        return Err(TdParseError::NotTdx(tee_type));
    }

    let body = HEADER_LEN;
    let mut rtmr = [[0u8; 48]; RTMR_COUNT];
    for (i, slot) in rtmr.iter_mut().enumerate() {
        *slot = arr48(quote, body + B_RTMR0 + i * MR_LEN);
    }
    let mut report_data = [0u8; 64];
    report_data.copy_from_slice(&quote[body + B_REPORTDATA..body + B_REPORTDATA + 64]);

    Ok(TdQuoteBody {
        version,
        tee_type,
        mrtd: arr48(quote, body + B_MRTD),
        mr_config_id: arr48(quote, body + B_MRCONFIGID),
        rtmr,
        report_data,
    })
}

/// The field comparison a real verifier runs **after** the chain checks out —
/// exposed and tested directly (as [`crate::snp::policy_forbids_debug`] is),
/// because with the chain gate closed it can never run inside a `Genuine` path.
/// Returns the first failing field's name, or `Ok(())` if every pinned field
/// matches. Comparing unauthenticated bytes proves nothing on its own — this is
/// only sound once the quote is authenticated.
pub fn check_bound_fields(body: &TdQuoteBody, expected: &TdxExpected) -> Result<(), &'static str> {
    if body.mrtd != expected.mrtd {
        return Err("mrtd — not the expected genuine TD build measurement");
    }
    if let Some(cfg) = &expected.mr_config_id {
        if &body.mr_config_id != cfg {
            return Err("mrconfigid — launch-config binding does not match the audited image");
        }
    }
    if let Some(rtmr) = &expected.rtmr {
        if &body.rtmr != rtmr {
            return Err("rtmr — runtime measured-boot registers do not match");
        }
    }
    if body.report_data != expected.report_data {
        return Err("report_data — nonce/channel binding mismatch (stale, replayed, or relayed quote)");
    }
    Ok(())
}

/// The no-collateral fail-closed gate. Without Intel PCS/DCAP collateral there
/// is nothing to authenticate a quote *against*, so this returns `Err`
/// unconditionally — the honest reason [`verify_td_quote`] can never be
/// `Genuine`. The real chain verification, when collateral IS available, is
/// [`verify_collateral_dcap`] (feature `tdx-verify`).
pub fn verify_collateral(_quote: &[u8]) -> Result<(), &'static str> {
    Err(
        "no TDX collateral supplied — the PCK → Intel processor CA → pinned Intel \
         SGX Root CA chain, QE report binding, and CRL/TCB freshness need Intel \
         PCS/DCAP collateral; fetch it and call verify_collateral_dcap (feature \
         `tdx-verify`); refusing to authenticate without it",
    )
}

/// Verify a TDX TD quote against `expected`. **Never returns `Genuine`** — the
/// collateral chain gate ([`verify_collateral`]) is unconditionally closed, so
/// the strongest possible verdict is [`crate::Verdict::Unverified`]. The quote
/// is parsed for real (so malformed input gets a precise reason), but the trust
/// decision fails closed BEFORE any field comparison can grant trust — the
/// same authenticate-then-compare order as [`crate::snp::verify_snp_report`].
///
/// **This function's behavior does NOT change when `tdx-verify` is compiled
/// in** — that split is intentional and permanent (see the module-level
/// "RESOLVED" note above). If you have `TdxCollateral` in hand, call
/// `verify_td_quote_with_collateral` (feature `tdx-verify`) instead — it is
/// the ONLY function in this module that can ever return `Genuine`.
pub fn verify_td_quote(quote: &[u8], _expected: &TdxExpected) -> crate::Verdict {
    // Parse first only to give an honest, specific reason on malformed input.
    if let Err(e) = parse_td_quote(quote) {
        return crate::Verdict::Unverified(match e {
            TdParseError::TooShort => "TDX quote is too short to be a v4 TD 1.0 report",
            TdParseError::UnsupportedVersion(_) => "TDX quote version is unsupported (want v4)",
            TdParseError::NotTdx(_) => "quote tee_type is not TDX",
        });
    }
    // Authenticate. This gate is closed on purpose — SEV-SNP is the supported
    // TEE (feature `sev-snp`). A well-formed, field-matching quote still stops
    // here: we will not say Genuine on a chain we cannot check.
    if verify_collateral(quote).is_err() {
        return crate::Verdict::Unverified(
            "TDX quote verification is not implemented — the Intel PCS chain check \
             (PCK → processor CA → pinned Intel root, TCB/QE collateral) has not \
             landed; refusing to guess. SEV-SNP is the supported TEE (feature `sev-snp`).",
        );
    }
    // Unreachable while the gate is closed; kept so the shape is complete.
    crate::Verdict::Unverified("TDX verification reached an unexpected state — failing closed")
}

/// Convenience: recompute the channel binding from OUR nonce and the guest
/// pubkey and fold it into `expected` before verification — the TDX analogue of
/// [`crate::snp::verify_gate_evidence`]. Still fail-closed (never `Genuine`) —
/// **and stays that way even with `tdx-verify` compiled in**; this name and
/// `verify_td_quote_with_collateral` are permanently separate entry points
/// (module-level "RESOLVED" note above), not two states of the same function.
pub fn verify_td_quote_bound(
    quote: &[u8],
    nonce: &[u8; 32],
    guest_pubkey: &[u8],
    mut expected: TdxExpected,
) -> crate::Verdict {
    expected.report_data = binding::report_data(nonce, guest_pubkey);
    verify_td_quote(quote, &expected)
}

// ───────────────────── Intel PCS/DCAP collateral verification ─────────────────
//
// The real (dcap-qvl-style) quote-signature chain, behind feature `tdx-verify`.
// Pure Rust: `x509-parser`/ring for the PCK X.509 chain + CRLs, `p256` for the
// raw ECDSA over the quote/QE-report/attestation-key bindings, `sha2` for the
// QE-report binding digest. See this module's header for the honest limits —
// most importantly, the pinned Intel root is a placeholder, so the pinned
// entry never returns Ok on this host and TDX never mints `Genuine` here.
#[cfg(feature = "tdx-verify")]
pub use dcap::{
    verify_collateral_anchored, verify_collateral_dcap, verify_td_quote_with_collateral,
    TdxCollateral, TdxCollateralError, TdxJsonCollateral, PINNED_INTEL_SGX_ROOT_CA_DER,
};

#[cfg(feature = "tdx-verify")]
mod dcap {
    use super::{check_bound_fields, parse_td_quote, TdxExpected, HEADER_LEN, TD_BODY_LEN};
    use sha2::{Digest, Sha256};
    use x509_parser::asn1_rs::{Any, Oid};
    use x509_parser::pem::Pem;
    use x509_parser::prelude::{FromDer, X509Certificate};
    use x509_parser::revocation_list::CertificateRevocationList;
    use x509_parser::time::ASN1Time;

    /// The pinned Intel SGX Provisioning Certification **Root CA** (DER). The
    /// anchor the PCK chain must terminate at — the TDX analogue of SNP's
    /// compiled-in AMD ARK.
    ///
    /// This is Intel's genuine, published SGX Root CA, fetched from
    /// <https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.cer>
    /// (served in DER form) and embedded verbatim. Identifying facts (all
    /// asserted by `tests/tdx_collateral.rs`):
    ///   • self-signed X.509v3, subject == issuer
    ///     `CN=Intel SGX Root CA, O=Intel Corporation, L=Santa Clara, ST=CA, C=US`;
    ///   • P-256 (`prime256v1`) key, `ecdsa-with-SHA256` signature;
    ///   • serial `22650CD65A9D3489F383B49552BF501B392706AC`;
    ///   • SHA-256 fingerprint
    ///     `44A0196B2B99F889B8E149E95B807A350E7424964399E885A7CBB8CCFAB674D3`;
    ///   • 659 bytes.
    ///
    /// HONESTY: pinning this root only makes the PCK → processor CA → root chain
    /// *authenticatable*. It does NOT mean any real TDX quote has been verified —
    /// reaching `Genuine` still needs a genuine Intel TDX quote + matching
    /// collateral from silicon we launched (hardware-gated). Do NOT replace these
    /// bytes with anything but Intel's genuine root — that anchor is the whole
    /// trust decision. UNAUDITED.
    pub const PINNED_INTEL_SGX_ROOT_CA_DER: &[u8] = &[
        0x30, 0x82, 0x02, 0x8f, 0x30, 0x82, 0x02, 0x34, 0xa0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x14, 0x22, 0x65, 0x0c, 0xd6, 0x5a, 0x9d, 0x34, 0x89, 0xf3,
        0x83, 0xb4, 0x95, 0x52, 0xbf, 0x50, 0x1b, 0x39, 0x27, 0x06, 0xac, 0x30,
        0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
        0x68, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x11,
        0x49, 0x6e, 0x74, 0x65, 0x6c, 0x20, 0x53, 0x47, 0x58, 0x20, 0x52, 0x6f,
        0x6f, 0x74, 0x20, 0x43, 0x41, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x03, 0x55,
        0x04, 0x0a, 0x0c, 0x11, 0x49, 0x6e, 0x74, 0x65, 0x6c, 0x20, 0x43, 0x6f,
        0x72, 0x70, 0x6f, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x31, 0x14, 0x30,
        0x12, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x0b, 0x53, 0x61, 0x6e, 0x74,
        0x61, 0x20, 0x43, 0x6c, 0x61, 0x72, 0x61, 0x31, 0x0b, 0x30, 0x09, 0x06,
        0x03, 0x55, 0x04, 0x08, 0x0c, 0x02, 0x43, 0x41, 0x31, 0x0b, 0x30, 0x09,
        0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x30, 0x1e, 0x17,
        0x0d, 0x31, 0x38, 0x30, 0x35, 0x32, 0x31, 0x31, 0x30, 0x34, 0x35, 0x31,
        0x30, 0x5a, 0x17, 0x0d, 0x34, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33,
        0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x68, 0x31, 0x1a, 0x30, 0x18, 0x06,
        0x03, 0x55, 0x04, 0x03, 0x0c, 0x11, 0x49, 0x6e, 0x74, 0x65, 0x6c, 0x20,
        0x53, 0x47, 0x58, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x31,
        0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x11, 0x49, 0x6e,
        0x74, 0x65, 0x6c, 0x20, 0x43, 0x6f, 0x72, 0x70, 0x6f, 0x72, 0x61, 0x74,
        0x69, 0x6f, 0x6e, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x07,
        0x0c, 0x0b, 0x53, 0x61, 0x6e, 0x74, 0x61, 0x20, 0x43, 0x6c, 0x61, 0x72,
        0x61, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x02,
        0x43, 0x41, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
        0x02, 0x55, 0x53, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
        0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x0b, 0xa9, 0xc4, 0xc0, 0xc0, 0xc8,
        0x61, 0x93, 0xa3, 0xfe, 0x23, 0xd6, 0xb0, 0x2c, 0xda, 0x10, 0xa8, 0xbb,
        0xd4, 0xe8, 0x8e, 0x48, 0xb4, 0x45, 0x85, 0x61, 0xa3, 0x6e, 0x70, 0x55,
        0x25, 0xf5, 0x67, 0x91, 0x8e, 0x2e, 0xdc, 0x88, 0xe4, 0x0d, 0x86, 0x0b,
        0xd0, 0xcc, 0x4e, 0xe2, 0x6a, 0xac, 0xc9, 0x88, 0xe5, 0x05, 0xa9, 0x53,
        0x55, 0x8c, 0x45, 0x3f, 0x6b, 0x09, 0x04, 0xae, 0x73, 0x94, 0xa3, 0x81,
        0xbb, 0x30, 0x81, 0xb8, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04,
        0x18, 0x30, 0x16, 0x80, 0x14, 0x22, 0x65, 0x0c, 0xd6, 0x5a, 0x9d, 0x34,
        0x89, 0xf3, 0x83, 0xb4, 0x95, 0x52, 0xbf, 0x50, 0x1b, 0x39, 0x27, 0x06,
        0xac, 0x30, 0x52, 0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, 0x4b, 0x30, 0x49,
        0x30, 0x47, 0xa0, 0x45, 0xa0, 0x43, 0x86, 0x41, 0x68, 0x74, 0x74, 0x70,
        0x73, 0x3a, 0x2f, 0x2f, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63,
        0x61, 0x74, 0x65, 0x73, 0x2e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64,
        0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x69, 0x6e, 0x74,
        0x65, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x49, 0x6e, 0x74, 0x65, 0x6c,
        0x53, 0x47, 0x58, 0x52, 0x6f, 0x6f, 0x74, 0x43, 0x41, 0x2e, 0x64, 0x65,
        0x72, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14,
        0x22, 0x65, 0x0c, 0xd6, 0x5a, 0x9d, 0x34, 0x89, 0xf3, 0x83, 0xb4, 0x95,
        0x52, 0xbf, 0x50, 0x1b, 0x39, 0x27, 0x06, 0xac, 0x30, 0x0e, 0x06, 0x03,
        0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06,
        0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08,
        0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x01, 0x30, 0x0a, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30,
        0x46, 0x02, 0x21, 0x00, 0xe5, 0xbf, 0xe5, 0x09, 0x11, 0xf9, 0x2f, 0x42,
        0x89, 0x20, 0xdc, 0x36, 0x8a, 0x30, 0x2e, 0xe3, 0xd1, 0x2e, 0xc5, 0x86,
        0x7f, 0xf6, 0x22, 0xec, 0x64, 0x97, 0xf7, 0x80, 0x60, 0xc1, 0x3c, 0x20,
        0x02, 0x21, 0x00, 0xe0, 0x9d, 0x25, 0xac, 0x7a, 0x0c, 0xb3, 0xe5, 0xe8,
        0xe6, 0x8f, 0xec, 0x5f, 0xa3, 0xbd, 0x41, 0x6c, 0x47, 0x44, 0x0b, 0xd9,
        0x50, 0x63, 0x9d, 0x45, 0x0e, 0xdc, 0xbe, 0xa4, 0x57, 0x6a, 0xa2,
    ];

    // ── DCAP v4 ECDSA signature-section layout (Intel `sgx_quote_4.h`) ────────
    //
    // Absolute quote layout: header(48) ‖ td_body(584) ‖ sig_data_len(u32) ‖
    // sig_data. The sig_data (ECDSA-P256) is:
    //   sig(64) ‖ att_pub_key(64) ‖ outer_cert{type u16, size u32, data} where
    //   the outer cert data (type 6, QE report certification) is:
    //     qe_report(384) ‖ qe_report_sig(64) ‖ qe_auth{size u16, data} ‖
    //     pck_cert{type u16 (=5), size u32, PEM chain}
    const SIG_DATA_LEN_OFF: usize = HEADER_LEN + TD_BODY_LEN; // 632
    const QUOTE_SIGNED_LEN: usize = HEADER_LEN + TD_BODY_LEN; // header‖body is the signed message
    const SIG_LEN: usize = 64;
    const ATT_PUB_LEN: usize = 64;
    const QE_REPORT_LEN: usize = 384;
    /// `report_data` sits in the last 64 bytes of the 384-byte SGX report body.
    const QE_REPORT_DATA_OFF: usize = 320;
    const CERT_TYPE_QE_REPORT: u16 = 6;
    const CERT_TYPE_PCK_CHAIN: u16 = 5;
    /// TEE_TCB_SVN is the first 16 bytes of the TD report body.
    const TEE_TCB_SVN_LEN: usize = 16;

    /// Intel PCS/DCAP collateral fetched out of band (this crate does no network
    /// I/O). The PCK cert chain itself travels *inside* the quote, so only the
    /// CRLs, the freshness clock, and the anti-rollback floor live here.
    #[derive(Debug, Clone, Default)]
    pub struct TdxCollateral {
        /// Intel SGX Root CA CRL (DER), signed by the root; revokes intermediates.
        pub root_ca_crl_der: Option<Vec<u8>>,
        /// Intel SGX PCK Processor/Platform CA CRL (DER), signed by the
        /// intermediate; revokes PCK leaves.
        pub pck_crl_der: Option<Vec<u8>>,
        /// Verifier's current time (Unix seconds) for CRL `nextUpdate` freshness.
        pub now_unix: i64,
        /// Anti-rollback floor on the TD report's `TEE_TCB_SVN` (component-wise
        /// `>=`); `None` waives.
        pub tcb_svn_floor: Option<[u8; TEE_TCB_SVN_LEN]>,
        /// Intel PCS **TCB-Info + QE-Identity JSON** collateral, fetched out of
        /// band. `None` waives the JSON checks entirely (documented, exactly like
        /// a `None` CRL) — the chain/CRL/QE-binding checks still run. When
        /// `Some`, [`verify_collateral_anchored`] folds in: the TCB-signing-cert
        /// chain to the anchored Intel root, the TCB-Info + QE-Identity signature
        /// over their raw signed bodies, `nextUpdate` freshness, the matched TCB
        /// **status**, and the cross-checks against the quote/PCK (FMSPC, the
        /// SGX+TDX TCB components, and the QE report's identity + ISV SVN).
        pub json: Option<TdxJsonCollateral>,
    }

    /// Intel PCS **TCB-Info + QE-Identity JSON** collateral, fetched out of band
    /// (`GET .../tdx/certification/v4/tcb?fmspc=…` and `.../qe/identity`). The
    /// crate does no network I/O; the operator hands the raw response bytes and
    /// the issuer-chain PEM (the `TCB-Info-Issuer-Chain` /
    /// `SGX-Enclave-Identity-Issuer-Chain` HTTP header) in verbatim, so the
    /// signed bytes are byte-exact and the signature can be re-checked offline.
    #[derive(Debug, Clone, Default)]
    pub struct TdxJsonCollateral {
        /// The full TCB-Info response body: `{"tcbInfo":{…},"signature":"<hex>"}`.
        /// The signature covers the **raw bytes** of the `tcbInfo` value as
        /// served — this crate re-slices that exact span, never re-serializes.
        pub tcb_info_json: Vec<u8>,
        /// The full QE-Identity response body:
        /// `{"enclaveIdentity":{…},"signature":"<hex>"}`.
        pub qe_identity_json: Vec<u8>,
        /// The Intel TCB **signing** cert chain (PEM): signing cert ‖ Intel SGX
        /// Root CA. The signing cert must chain to the anchored root; its key
        /// verifies both JSON signatures.
        pub issuer_chain_pem: Vec<u8>,
    }

    /// Why a TD quote could not be authenticated against its collateral. Every
    /// reason is a hard, fail-closed refusal.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum TdxCollateralError {
        /// The pinned Intel SGX Root CA is not populated — refuse to anchor.
        PinnedRootUnset,
        /// The quote's signature section was malformed / truncated.
        MalformedSig(&'static str),
        /// The embedded PCK PEM chain was missing certs or unparseable.
        BadPckChain,
        /// The PCK chain does not chain leaf → intermediate → root by signature.
        ChainInvalid,
        /// The chain's root does not equal the pinned/anchor Intel root.
        RootNotAnchored,
        /// A CRL failed to parse, was not signed by its issuer, or was stale.
        CrlInvalid(&'static str),
        /// A cert in the chain is listed as revoked by the relevant CRL.
        Revoked,
        /// A PCK-chain cert (leaf, intermediate, or root) is outside its X.509
        /// `notBefore`/`notAfter` validity window at `collateral.now_unix`.
        /// Named which link, mirroring [`crate::mobile`]'s
        /// `certificate validity` check.
        CertExpired(&'static str),
        /// The QE report's `report_data` is not `SHA-256(att_pub_key ‖ qe_auth)`.
        QeBindingMismatch,
        /// The QE report is not signed by the PCK leaf.
        QeReportSignature,
        /// The quote body is not signed by the attestation key.
        QuoteSignature,
        /// The TD report's `TEE_TCB_SVN` is below the configured floor.
        TcbTooLow,
        /// A TCB-Info / QE-Identity JSON body was structurally malformed (missing
        /// a required field, a bad hex/timestamp, or a signed span we could not
        /// isolate). Named for an honest UI line.
        JsonMalformed(&'static str),
        /// The Intel TCB **signing** cert chain (from the issuer-chain PEM) did
        /// not verify: missing certs, not signed by the anchored root, the root
        /// is not the anchor, or a cert is outside its validity window.
        TcbSigningChainInvalid(&'static str),
        /// The TCB-Info `signature` does not verify over its raw `tcbInfo` body
        /// under the Intel TCB signing cert.
        TcbInfoSignature,
        /// The QE-Identity `signature` does not verify over its raw
        /// `enclaveIdentity` body under the Intel TCB signing cert.
        QeIdentitySignature,
        /// A TCB-Info / QE-Identity JSON is stale: `nextUpdate` is at//before the
        /// verifier's `now_unix`. Named which document.
        CollateralExpired(&'static str),
        /// The TCB-Info `fmspc` does not equal the PCK leaf's FMSPC extension —
        /// the collateral is for a different platform than the quote's PCK.
        FmspcMismatch,
        /// No TCB level in the TCB-Info is satisfied by the quote's TDX
        /// `TEE_TCB_SVN` + the PCK's SGX TCB components/`pcesvn` — an unknown or
        /// under-floor platform TCB. Fail closed.
        TcbLevelNotFound,
        /// The matched TCB-Info TCB level's `tcbStatus` is not `UpToDate` (e.g.
        /// `OutOfDate`, `Revoked`, `ConfigurationNeeded`). Strict fail-closed.
        TcbStatusUnacceptable,
        /// A QE-Identity field (mrsigner / isvprodid / masked miscselect /
        /// masked attributes) does not match the quote's QE report. Named which.
        QeIdentityMismatch(&'static str),
        /// No QE-Identity TCB level is satisfied by the QE report's ISV SVN, or
        /// the matched level's `tcbStatus` is not `UpToDate`. Fail closed.
        QeTcbStatusUnacceptable,
    }

    impl core::fmt::Display for TdxCollateralError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            use TdxCollateralError::*;
            match self {
                PinnedRootUnset => write!(f, "pinned Intel SGX Root CA is unset — cannot anchor the chain"),
                MalformedSig(w) => write!(f, "malformed TD quote signature section: {w}"),
                BadPckChain => write!(f, "PCK certificate chain missing/unparseable"),
                ChainInvalid => write!(f, "PCK chain does not verify to its issuer"),
                RootNotAnchored => write!(f, "PCK chain root is not the pinned Intel SGX Root CA"),
                CrlInvalid(w) => write!(f, "Intel PCS CRL invalid: {w}"),
                Revoked => write!(f, "a certificate in the PCK chain is revoked"),
                CertExpired(which) => write!(f, "PCK chain certificate expired/not-yet-valid: {which}"),
                QeBindingMismatch => write!(f, "QE report_data != SHA-256(att_pub_key ‖ qe_auth)"),
                QeReportSignature => write!(f, "QE report is not signed by the PCK"),
                QuoteSignature => write!(f, "TD quote is not signed by the attestation key"),
                TcbTooLow => write!(f, "TEE_TCB_SVN below the anti-rollback floor"),
                JsonMalformed(w) => write!(f, "malformed TCB-Info/QE-Identity JSON: {w}"),
                TcbSigningChainInvalid(w) => write!(f, "Intel TCB signing cert chain invalid: {w}"),
                TcbInfoSignature => write!(f, "TCB-Info signature does not verify under the Intel TCB signing cert"),
                QeIdentitySignature => write!(f, "QE-Identity signature does not verify under the Intel TCB signing cert"),
                CollateralExpired(w) => write!(f, "Intel collateral stale (nextUpdate elapsed): {w}"),
                FmspcMismatch => write!(f, "TCB-Info fmspc != PCK certificate FMSPC"),
                TcbLevelNotFound => write!(f, "no TCB-Info level satisfied by the quote/PCK TCB"),
                TcbStatusUnacceptable => write!(f, "matched TCB-Info level tcbStatus is not UpToDate"),
                QeIdentityMismatch(w) => write!(f, "QE-Identity mismatch against the QE report: {w}"),
                QeTcbStatusUnacceptable => write!(f, "QE-Identity ISV SVN below level / tcbStatus not UpToDate"),
            }
        }
    }

    /// The borrowed fields of a parsed v4 ECDSA signature section. Nothing here
    /// is authenticated — that is the job of the verification below.
    struct EcdsaSigSection<'a> {
        quote_sig: &'a [u8],
        att_pub_key: &'a [u8],
        qe_report: &'a [u8],
        qe_report_sig: &'a [u8],
        qe_auth: &'a [u8],
        pck_chain_pem: &'a [u8],
    }

    fn le_u16(b: &[u8], at: usize) -> Option<u16> {
        Some(u16::from_le_bytes([*b.get(at)?, *b.get(at + 1)?]))
    }
    fn le_u32(b: &[u8], at: usize) -> Option<u32> {
        Some(u32::from_le_bytes([*b.get(at)?, *b.get(at + 1)?, *b.get(at + 2)?, *b.get(at + 3)?]))
    }
    fn take<'a>(b: &'a [u8], at: usize, len: usize) -> Option<&'a [u8]> {
        b.get(at..at.checked_add(len)?)
    }

    /// Structurally decode the ECDSA signature section. Every read is bounds
    /// checked; a short or self-inconsistent buffer is a named `MalformedSig`.
    fn parse_ecdsa_sig_section(quote: &[u8]) -> Result<EcdsaSigSection<'_>, TdxCollateralError> {
        use TdxCollateralError::MalformedSig;
        let sig_len = le_u32(quote, SIG_DATA_LEN_OFF).ok_or(MalformedSig("sig_data_len"))? as usize;
        let sig_start = SIG_DATA_LEN_OFF + 4;
        let sig_data = take(quote, sig_start, sig_len).ok_or(MalformedSig("sig_data truncated"))?;

        let quote_sig = take(sig_data, 0, SIG_LEN).ok_or(MalformedSig("quote sig"))?;
        let att_pub_key = take(sig_data, SIG_LEN, ATT_PUB_LEN).ok_or(MalformedSig("att pub key"))?;

        let mut at = SIG_LEN + ATT_PUB_LEN;
        let outer_type = le_u16(sig_data, at).ok_or(MalformedSig("outer cert type"))?;
        let outer_size = le_u32(sig_data, at + 2).ok_or(MalformedSig("outer cert size"))? as usize;
        at += 6;
        if outer_type != CERT_TYPE_QE_REPORT {
            return Err(MalformedSig("outer cert type is not QE-report (6)"));
        }
        let outer = take(sig_data, at, outer_size).ok_or(MalformedSig("outer cert data"))?;

        // Inside the QE-report certification data.
        let qe_report = take(outer, 0, QE_REPORT_LEN).ok_or(MalformedSig("qe report"))?;
        let qe_report_sig = take(outer, QE_REPORT_LEN, SIG_LEN).ok_or(MalformedSig("qe report sig"))?;
        let mut io = QE_REPORT_LEN + SIG_LEN;
        let qe_auth_size = le_u16(outer, io).ok_or(MalformedSig("qe auth size"))? as usize;
        io += 2;
        let qe_auth = take(outer, io, qe_auth_size).ok_or(MalformedSig("qe auth data"))?;
        io += qe_auth_size;
        let pck_type = le_u16(outer, io).ok_or(MalformedSig("pck cert type"))?;
        let pck_size = le_u32(outer, io + 2).ok_or(MalformedSig("pck cert size"))? as usize;
        io += 6;
        if pck_type != CERT_TYPE_PCK_CHAIN {
            return Err(MalformedSig("inner cert type is not PCK-chain (5)"));
        }
        let pck_chain_pem = take(outer, io, pck_size).ok_or(MalformedSig("pck cert data"))?;

        Ok(EcdsaSigSection { quote_sig, att_pub_key, qe_report, qe_report_sig, qe_auth, pck_chain_pem })
    }

    /// Raw ECDSA-P256 verify: `pubkey_sec1` is `0x04‖x‖y` (65) or `x‖y` (64);
    /// `sig` is fixed 64-byte `r‖s`; the message is hashed with SHA-256.
    fn ecdsa_p256_verify(pubkey_sec1: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        use p256::ecdsa::signature::Verifier;
        use p256::ecdsa::{Signature, VerifyingKey};
        let vk = match pubkey_sec1.len() {
            65 => VerifyingKey::from_sec1_bytes(pubkey_sec1),
            64 => {
                let mut sec1 = [0u8; 65];
                sec1[0] = 0x04;
                sec1[1..].copy_from_slice(pubkey_sec1);
                VerifyingKey::from_sec1_bytes(&sec1)
            }
            _ => return false,
        };
        let (Ok(vk), Ok(sig)) = (vk, Signature::from_slice(sig)) else {
            return false;
        };
        vk.verify(msg, &sig).is_ok()
    }

    /// Verify a CRL (DER) is signed by `issuer`, is fresh at `now_unix`, and does
    /// not list `subject_serial`. `None` CRL means "not supplied" → Ok (waived,
    /// documented by the caller passing `None`).
    fn check_crl(
        crl_der: Option<&Vec<u8>>,
        issuer: &X509Certificate,
        subject_serial: &[u8],
        now_unix: i64,
    ) -> Result<(), TdxCollateralError> {
        use TdxCollateralError::{CrlInvalid, Revoked};
        let Some(der) = crl_der else { return Ok(()) };
        let (_, crl) = CertificateRevocationList::from_der(der).map_err(|_| CrlInvalid("parse"))?;
        crl.verify_signature(issuer.public_key()).map_err(|_| CrlInvalid("signature"))?;
        match crl.next_update() {
            Some(nu) if now_unix <= nu.timestamp() => {}
            _ => return Err(CrlInvalid("stale (nextUpdate elapsed)")),
        }
        if crl.iter_revoked_certificates().any(|r| r.raw_serial() == subject_serial) {
            return Err(Revoked);
        }
        Ok(())
    }

    // ── Intel TCB-Info + QE-Identity JSON collateral ─────────────────────────
    //
    // Intel signs the RAW bytes of the inner `tcbInfo` / `enclaveIdentity` value
    // (as served) with the Intel TCB signing cert; the enclosing object also
    // carries a hex `signature`. So we (a) re-slice that exact inner span for the
    // signed message (never re-serialize — JSON re-encoding changes bytes), and
    // (b) read the fields we cross-check with serde_json's value tree. The signing
    // cert chains to the SAME anchored Intel root as the PCK chain.

    /// SGX PCK-certificate extension OID `1.2.840.113741.1.13.1`, and the child
    /// OIDs we read out of it (FMSPC + the SGX TCB components + PCESVN).
    const OID_SGX_EXT: &[u64] = &[1, 2, 840, 113741, 1, 13, 1];
    const OID_SGX_TCB: &[u64] = &[1, 2, 840, 113741, 1, 13, 1, 2];
    const OID_SGX_FMSPC: &[u64] = &[1, 2, 840, 113741, 1, 13, 1, 4];
    const OID_SGX_PCESVN: &[u64] = &[1, 2, 840, 113741, 1, 13, 1, 2, 17];

    /// The SGX-side TCB coordinates read from a PCK leaf's Intel extension — the
    /// half of a TCB-level match that does NOT come from the TDX quote body.
    struct PckSgxTcb {
        fmspc: [u8; 6],
        pcesvn: u16,
        /// `sgxtcbcomp01svn` .. `sgxtcbcomp16svn`.
        comps: [u8; 16],
    }

    /// Iterate the DER elements of a SEQUENCE-shaped [`Any`] (its `data` is the
    /// concatenated child TLVs). Stops at the first malformed tail, so a
    /// truncated extension yields the prefix it could parse (callers then miss a
    /// required field and fail closed — never read out of bounds).
    fn der_children<'a>(seq: &Any<'a>) -> Vec<Any<'a>> {
        let mut out = Vec::new();
        let mut d: &[u8] = seq.data;
        while !d.is_empty() {
            match Any::from_der(d) {
                Ok((rest, item)) => {
                    out.push(item);
                    d = rest;
                }
                Err(_) => break,
            }
        }
        out
    }

    /// A child SEQUENCE `{ OID, value }` → its OID and the value `Any`.
    fn oid_and_value<'a>(item: &Any<'a>) -> Option<(Oid<'a>, Any<'a>)> {
        let (rest, oid) = Oid::from_der(item.data).ok()?;
        let (_, val) = Any::from_der(rest).ok()?;
        Some((oid, val))
    }

    /// Big-endian unsigned integer from an ASN.1 INTEGER's content bytes.
    fn be_uint(bytes: &[u8]) -> u64 {
        let mut v: u64 = 0;
        for &b in bytes {
            v = (v << 8) | b as u64;
        }
        v
    }

    /// Parse the PCK leaf's Intel SGX extension for the FMSPC, PCESVN, and the 16
    /// SGX TCB components. `None` if the extension is absent or malformed (the
    /// caller then fails closed — a TDX PCK leaf always carries this extension).
    fn parse_pck_sgx_tcb(pck: &X509Certificate) -> Option<PckSgxTcb> {
        let ext_oid = Oid::from(OID_SGX_EXT).ok()?;
        let ext = pck.extensions().iter().find(|e| e.oid == ext_oid)?;
        let (_, outer) = Any::from_der(ext.value).ok()?;

        let tcb_oid = Oid::from(OID_SGX_TCB).ok()?;
        let fmspc_oid = Oid::from(OID_SGX_FMSPC).ok()?;
        let pcesvn_oid = Oid::from(OID_SGX_PCESVN).ok()?;
        let comp_oids: Vec<Oid> = (1..=16u64)
            .map(|i| {
                let mut arcs = OID_SGX_TCB.to_vec();
                arcs.push(i);
                Oid::from(&arcs).unwrap()
            })
            .collect();

        let mut fmspc: Option<[u8; 6]> = None;
        let mut pcesvn: Option<u16> = None;
        let mut comps = [0u8; 16];
        let mut got_comps = 0u32;

        for item in der_children(&outer) {
            let Some((oid, val)) = oid_and_value(&item) else { continue };
            if oid == fmspc_oid {
                if val.data.len() == 6 {
                    let mut f = [0u8; 6];
                    f.copy_from_slice(val.data);
                    fmspc = Some(f);
                }
            } else if oid == tcb_oid {
                for sub in der_children(&val) {
                    let Some((soid, sval)) = oid_and_value(&sub) else { continue };
                    if soid == pcesvn_oid {
                        pcesvn = Some(be_uint(sval.data) as u16);
                    } else if let Some(i) = comp_oids.iter().position(|c| *c == soid) {
                        comps[i] = be_uint(sval.data) as u8;
                        got_comps += 1;
                    }
                }
            }
        }

        if got_comps != 16 {
            return None;
        }
        Some(PckSgxTcb { fmspc: fmspc?, pcesvn: pcesvn?, comps })
    }

    /// Decode a hex string to bytes (fail closed on odd length / bad nibble).
    fn hex_decode(s: &str) -> Option<Vec<u8>> {
        let b = s.as_bytes();
        if b.len() & 1 != 0 {
            return None;
        }
        let nib = |c: u8| -> Option<u8> {
            match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                b'A'..=b'F' => Some(c - b'A' + 10),
                _ => None,
            }
        };
        let mut out = Vec::with_capacity(b.len() / 2);
        for pair in b.chunks(2) {
            out.push((nib(pair[0])? << 4) | nib(pair[1])?);
        }
        Some(out)
    }

    /// Parse a strict `YYYY-MM-DDTHH:MM:SSZ` UTC instant (the format Intel PCS
    /// serves `issueDate`/`nextUpdate` in) to a Unix timestamp. `None` on any
    /// structural deviation — freshness then fails closed rather than guessing.
    fn iso8601_utc_to_unix(s: &str) -> Option<i64> {
        let b = s.as_bytes();
        // "2023-04-13T09:38:17Z" == 20 chars.
        if b.len() < 19 {
            return None;
        }
        let d = |i: usize| -> Option<i64> {
            let c = b[i];
            if c.is_ascii_digit() {
                Some((c - b'0') as i64)
            } else {
                None
            }
        };
        let num = |a: usize, n: usize| -> Option<i64> {
            let mut v = 0i64;
            for i in a..a + n {
                v = v * 10 + d(i)?;
            }
            Some(v)
        };
        if b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
            return None;
        }
        let (year, month, day) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
        let (hh, mm, ss) = (num(11, 2)?, num(14, 2)?, num(17, 2)?);
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hh > 23 || mm > 59 || ss > 60 {
            return None;
        }
        // days_from_civil (Howard Hinnant), valid for the proleptic Gregorian
        // calendar over the full range we need.
        let y = if month <= 2 { year - 1 } else { year };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400;
        let mp = (month + 9) % 12;
        let doy = (153 * mp + 2) / 5 + day - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146097 + doe - 719468;
        Some(days * 86400 + hh * 3600 + mm * 60 + ss)
    }

    /// Re-slice the byte span of the JSON object value under top-level `key`
    /// (`{ … }`), string- and escape-aware, so it is exactly what Intel signed.
    /// Returns the span INCLUDING the outer braces.
    fn raw_object_span<'a>(bytes: &'a [u8], key: &str) -> Option<&'a [u8]> {
        let needle_str = format!("\"{key}\"");
        let needle = needle_str.as_bytes();
        // Find the key token that sits OUTSIDE any string literal.
        let mut i = 0usize;
        let mut in_str = false;
        let mut esc = false;
        let mut key_at = None;
        while i < bytes.len() {
            let c = bytes[i];
            if in_str {
                if esc {
                    esc = false;
                } else if c == b'\\' {
                    esc = true;
                } else if c == b'"' {
                    in_str = false;
                }
                i += 1;
                continue;
            }
            if c == b'"' {
                if bytes[i..].starts_with(needle) {
                    key_at = Some(i);
                    break;
                }
                in_str = true;
                i += 1;
                continue;
            }
            i += 1;
        }
        let mut j = key_at? + needle.len();
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != b':' {
            return None;
        }
        j += 1;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != b'{' {
            return None;
        }
        let start = j;
        let mut depth = 0i32;
        let mut in_str = false;
        let mut esc = false;
        while j < bytes.len() {
            let c = bytes[j];
            if in_str {
                if esc {
                    esc = false;
                } else if c == b'\\' {
                    esc = true;
                } else if c == b'"' {
                    in_str = false;
                }
            } else {
                match c {
                    b'"' => in_str = true,
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(&bytes[start..=j]);
                        }
                    }
                    _ => {}
                }
            }
            j += 1;
        }
        None
    }

    /// Parse the issuer-chain PEM into (signing cert DER, root DER), verify the
    /// root equals the anchor, the signing cert is signed by the root, and both
    /// are inside their validity windows at `now_unix`. Returns the signing
    /// cert's raw SEC1 public key bytes (for the JSON signature checks).
    fn verify_signing_chain(
        issuer_chain_pem: &[u8],
        anchor_root_der: &[u8],
        now_unix: i64,
    ) -> Result<Vec<u8>, TdxCollateralError> {
        use TdxCollateralError::TcbSigningChainInvalid;
        let pems: Vec<Pem> = Pem::iter_from_buffer(issuer_chain_pem)
            .collect::<Result<_, _>>()
            .map_err(|_| TcbSigningChainInvalid("issuer chain PEM unparseable"))?;
        if pems.len() < 2 {
            return Err(TcbSigningChainInvalid("issuer chain needs signing cert + root"));
        }
        let signing_der = &pems[0].contents;
        let root_der = &pems[pems.len() - 1].contents;
        if root_der.as_slice() != anchor_root_der {
            return Err(TcbSigningChainInvalid("issuer-chain root is not the anchored Intel root"));
        }
        let (_, signing) =
            X509Certificate::from_der(signing_der).map_err(|_| TcbSigningChainInvalid("signing cert DER"))?;
        let (_, root) =
            X509Certificate::from_der(root_der).map_err(|_| TcbSigningChainInvalid("root cert DER"))?;
        root.verify_signature(None)
            .map_err(|_| TcbSigningChainInvalid("root not self-signed"))?;
        signing
            .verify_signature(Some(root.public_key()))
            .map_err(|_| TcbSigningChainInvalid("signing cert not signed by the anchored root"))?;
        let now = ASN1Time::from_timestamp(now_unix)
            .map_err(|_| TcbSigningChainInvalid("invalid verifier clock"))?;
        if !root.validity().is_valid_at(now) {
            return Err(TcbSigningChainInvalid("root outside validity window"));
        }
        if !signing.validity().is_valid_at(now) {
            return Err(TcbSigningChainInvalid("signing cert outside validity window"));
        }
        Ok(signing.public_key().subject_public_key.data.to_vec())
    }

    /// Verify a `{ "<body_key>": {…}, "signature": "<hex>" }` document: re-slice
    /// the raw signed body, decode the signature, and check it under
    /// `signing_pub` (raw SEC1). Returns the parsed body value on success.
    fn verify_json_signed(
        json: &[u8],
        body_key: &str,
        signing_pub: &[u8],
        sig_err: TdxCollateralError,
    ) -> Result<serde_json::Value, TdxCollateralError> {
        use TdxCollateralError::JsonMalformed;
        let signed = raw_object_span(json, body_key).ok_or(JsonMalformed("signed body span not found"))?;
        let top: serde_json::Value =
            serde_json::from_slice(json).map_err(|_| JsonMalformed("top-level JSON parse"))?;
        let sig_hex = top
            .get("signature")
            .and_then(|v| v.as_str())
            .ok_or(JsonMalformed("signature field missing"))?;
        let sig = hex_decode(sig_hex).ok_or(JsonMalformed("signature hex"))?;
        if sig.len() != 64 {
            return Err(JsonMalformed("signature is not a 64-byte P-256 r‖s"));
        }
        if !ecdsa_p256_verify(signing_pub, signed, &sig) {
            return Err(sig_err);
        }
        top.get(body_key)
            .cloned()
            .ok_or(JsonMalformed("body value missing"))
    }

    /// Read the 16 `svn` values of a TCB-level components array (`sgxtcbcomponents`
    /// or `tdxtcbcomponents`). `None` if it is not a 16-element array of `{svn}`.
    fn comp_svns(v: Option<&serde_json::Value>) -> Option<[u64; 16]> {
        let arr = v?.as_array()?;
        if arr.len() != 16 {
            return None;
        }
        let mut out = [0u64; 16];
        for (i, e) in arr.iter().enumerate() {
            out[i] = e.get("svn")?.as_u64()?;
        }
        Some(out)
    }

    /// Evaluate the TCB-Info: verify signature/chain/freshness, cross-check FMSPC
    /// against the PCK, select the TCB level satisfied by the PCK SGX components +
    /// PCESVN AND the quote's TDX `TEE_TCB_SVN`, and require its status UpToDate.
    fn verify_tcb_info(
        tcb_info_json: &[u8],
        signing_pub: &[u8],
        now_unix: i64,
        pck_sgx: &PckSgxTcb,
        tee_tcb_svn: &[u8],
    ) -> Result<(), TdxCollateralError> {
        use TdxCollateralError::*;
        let body = verify_json_signed(tcb_info_json, "tcbInfo", signing_pub, TcbInfoSignature)?;

        if body.get("id").and_then(|v| v.as_str()) != Some("TDX") {
            return Err(JsonMalformed("tcbInfo.id is not \"TDX\""));
        }
        let next_update = body
            .get("nextUpdate")
            .and_then(|v| v.as_str())
            .and_then(iso8601_utc_to_unix)
            .ok_or(JsonMalformed("tcbInfo.nextUpdate"))?;
        if now_unix >= next_update {
            return Err(CollateralExpired("tcbInfo"));
        }

        // FMSPC cross-check against the PCK leaf.
        let fmspc_hex = body.get("fmspc").and_then(|v| v.as_str()).ok_or(JsonMalformed("tcbInfo.fmspc"))?;
        let fmspc = hex_decode(fmspc_hex).ok_or(JsonMalformed("tcbInfo.fmspc hex"))?;
        if fmspc.as_slice() != pck_sgx.fmspc {
            return Err(FmspcMismatch);
        }

        // Select the first TCB level whose SGX components + pcesvn (from the PCK)
        // and TDX components (from the quote's TEE_TCB_SVN) are ALL satisfied.
        let levels = body.get("tcbLevels").and_then(|v| v.as_array()).ok_or(JsonMalformed("tcbInfo.tcbLevels"))?;
        if tee_tcb_svn.len() < 16 {
            return Err(JsonMalformed("TEE_TCB_SVN too short"));
        }
        let mut status: Option<String> = None;
        for lvl in levels {
            let tcb = lvl.get("tcb").ok_or(JsonMalformed("tcbLevel.tcb"))?;
            let Some(sgx) = comp_svns(tcb.get("sgxtcbcomponents")) else { continue };
            let Some(tdx) = comp_svns(tcb.get("tdxtcbcomponents")) else { continue };
            let Some(pcesvn) = tcb.get("pcesvn").and_then(|v| v.as_u64()) else { continue };
            let sgx_ok = (0..16).all(|i| pck_sgx.comps[i] as u64 >= sgx[i]);
            let tdx_ok = (0..16).all(|i| tee_tcb_svn[i] as u64 >= tdx[i]);
            if sgx_ok && tdx_ok && pck_sgx.pcesvn as u64 >= pcesvn {
                status = lvl.get("tcbStatus").and_then(|v| v.as_str()).map(str::to_string);
                break;
            }
        }
        match status.as_deref() {
            Some("UpToDate") => Ok(()),
            Some(_) => Err(TcbStatusUnacceptable),
            None => Err(TcbLevelNotFound),
        }
    }

    /// Evaluate the QE-Identity: verify signature/chain/freshness, then cross-check
    /// the QE report's identity (mrsigner, isvprodid, masked miscselect, masked
    /// attributes) and require an ISV-SVN-satisfied level with status UpToDate.
    fn verify_qe_identity(
        qe_identity_json: &[u8],
        signing_pub: &[u8],
        now_unix: i64,
        qe_report: &[u8],
    ) -> Result<(), TdxCollateralError> {
        use TdxCollateralError::*;
        // sgx_report_body_t field offsets inside the 384-byte QE report.
        const O_MISCSELECT: usize = 16;
        const O_ATTRIBUTES: usize = 48;
        const O_MRSIGNER: usize = 128;
        const O_ISVPRODID: usize = 256;
        const O_ISVSVN: usize = 258;
        if qe_report.len() < QE_REPORT_LEN {
            return Err(JsonMalformed("QE report too short"));
        }

        let body = verify_json_signed(qe_identity_json, "enclaveIdentity", signing_pub, QeIdentitySignature)?;
        if body.get("id").and_then(|v| v.as_str()) != Some("TD_QE") {
            return Err(JsonMalformed("enclaveIdentity.id is not \"TD_QE\""));
        }
        let next_update = body
            .get("nextUpdate")
            .and_then(|v| v.as_str())
            .and_then(iso8601_utc_to_unix)
            .ok_or(JsonMalformed("enclaveIdentity.nextUpdate"))?;
        if now_unix >= next_update {
            return Err(CollateralExpired("enclaveIdentity"));
        }

        let hexf = |k: &str| -> Result<Vec<u8>, TdxCollateralError> {
            let s = body.get(k).and_then(|v| v.as_str()).ok_or(JsonMalformed("enclaveIdentity field"))?;
            hex_decode(s).ok_or(JsonMalformed("enclaveIdentity hex field"))
        };

        // mrsigner (32 bytes) exact match.
        let mrsigner = hexf("mrsigner")?;
        if mrsigner.as_slice() != &qe_report[O_MRSIGNER..O_MRSIGNER + 32] {
            return Err(QeIdentityMismatch("mrsigner"));
        }
        // isvprodid (u16, little-endian in the report) exact match.
        let isvprodid = body.get("isvprodid").and_then(|v| v.as_u64()).ok_or(JsonMalformed("isvprodid"))?;
        let report_prodid =
            u16::from_le_bytes([qe_report[O_ISVPRODID], qe_report[O_ISVPRODID + 1]]) as u64;
        if isvprodid != report_prodid {
            return Err(QeIdentityMismatch("isvprodid"));
        }
        // miscselect (4) under mask.
        let (misc, misc_mask) = (hexf("miscselect")?, hexf("miscselectMask")?);
        if misc.len() != 4 || misc_mask.len() != 4 {
            return Err(JsonMalformed("miscselect/mask length"));
        }
        for i in 0..4 {
            if (qe_report[O_MISCSELECT + i] & misc_mask[i]) != (misc[i] & misc_mask[i]) {
                return Err(QeIdentityMismatch("miscselect"));
            }
        }
        // attributes (16) under mask.
        let (attr, attr_mask) = (hexf("attributes")?, hexf("attributesMask")?);
        if attr.len() != 16 || attr_mask.len() != 16 {
            return Err(JsonMalformed("attributes/mask length"));
        }
        for i in 0..16 {
            if (qe_report[O_ATTRIBUTES + i] & attr_mask[i]) != (attr[i] & attr_mask[i]) {
                return Err(QeIdentityMismatch("attributes"));
            }
        }

        // TCB level by ISV SVN: first level whose isvsvn the report meets; status
        // must be UpToDate.
        let report_isvsvn = u16::from_le_bytes([qe_report[O_ISVSVN], qe_report[O_ISVSVN + 1]]) as u64;
        let levels = body.get("tcbLevels").and_then(|v| v.as_array()).ok_or(JsonMalformed("enclaveIdentity.tcbLevels"))?;
        let mut status: Option<String> = None;
        for lvl in levels {
            let isvsvn = lvl.get("tcb").and_then(|t| t.get("isvsvn")).and_then(|v| v.as_u64());
            let Some(isvsvn) = isvsvn else { continue };
            if report_isvsvn >= isvsvn {
                status = lvl.get("tcbStatus").and_then(|v| v.as_str()).map(str::to_string);
                break;
            }
        }
        match status.as_deref() {
            Some("UpToDate") => Ok(()),
            _ => Err(QeTcbStatusUnacceptable),
        }
    }

    /// Fold in the Intel TCB-Info + QE-Identity JSON collateral: verify the TCB
    /// signing chain to the anchored root, both JSON signatures over their raw
    /// bodies, `nextUpdate` freshness, TCB **status**, and the cross-checks
    /// against the quote (FMSPC + SGX/TDX TCB components, QE identity + ISV SVN).
    fn verify_json_collateral(
        json: &TdxJsonCollateral,
        anchor_root_der: &[u8],
        now_unix: i64,
        pck_leaf: &X509Certificate,
        qe_report: &[u8],
        tee_tcb_svn: &[u8],
    ) -> Result<(), TdxCollateralError> {
        use TdxCollateralError::JsonMalformed;
        let signing_pub = verify_signing_chain(&json.issuer_chain_pem, anchor_root_der, now_unix)?;
        let pck_sgx = parse_pck_sgx_tcb(pck_leaf)
            .ok_or(JsonMalformed("PCK leaf is missing/!valid Intel SGX TCB extension"))?;
        verify_tcb_info(&json.tcb_info_json, &signing_pub, now_unix, &pck_sgx, tee_tcb_svn)?;
        verify_qe_identity(&json.qe_identity_json, &signing_pub, now_unix, qe_report)?;
        Ok(())
    }

    /// The real DCAP verification, anchored to an **explicitly supplied** root —
    /// the mechanism [`verify_collateral_dcap`] is built on. Splitting the anchor
    /// out lets the genuine crypto be exercised offline against a synthetic root
    /// in tests; **production uses [`verify_collateral_dcap`], which pins Intel's
    /// root.** Supplying a non-Intel anchor here trusts whatever you pass — tests
    /// only.
    pub fn verify_collateral_anchored(
        quote: &[u8],
        collateral: &TdxCollateral,
        anchor_root_der: &[u8],
    ) -> Result<(), TdxCollateralError> {
        use TdxCollateralError::*;
        if anchor_root_der.is_empty() {
            return Err(PinnedRootUnset);
        }
        let sig = parse_ecdsa_sig_section(quote)?;

        // 1. Split the embedded PCK PEM chain into leaf ‖ intermediate ‖ root.
        let pems: Vec<Pem> = Pem::iter_from_buffer(sig.pck_chain_pem)
            .collect::<Result<_, _>>()
            .map_err(|_| BadPckChain)?;
        if pems.len() < 3 {
            return Err(BadPckChain);
        }
        let leaf_der = &pems[0].contents;
        let inter_der = &pems[1].contents;
        let root_der = &pems[pems.len() - 1].contents;
        let (_, leaf) = X509Certificate::from_der(leaf_der).map_err(|_| BadPckChain)?;
        let (_, inter) = X509Certificate::from_der(inter_der).map_err(|_| BadPckChain)?;
        let (_, root) = X509Certificate::from_der(root_der).map_err(|_| BadPckChain)?;

        // 2. Anchor: the chain root must be exactly the pinned root, and be a
        //    valid self-signed cert. The root is never taken from the wire —
        //    presenting a different root just fails this equality.
        if root_der.as_slice() != anchor_root_der {
            return Err(RootNotAnchored);
        }
        root.verify_signature(None).map_err(|_| ChainInvalid)?;

        // 3. Chain signatures: leaf ← intermediate ← root.
        leaf.verify_signature(Some(inter.public_key())).map_err(|_| ChainInvalid)?;
        inter.verify_signature(Some(root.public_key())).map_err(|_| ChainInvalid)?;

        // 3b. Certificate validity windows (notBefore/notAfter), mirroring
        //     crate::mobile's `certificate validity` check. CRL `nextUpdate`
        //     freshness (step 4) tells you the REVOCATION LIST is fresh; it says
        //     nothing about whether the PCK leaf/intermediate/root certs
        //     THEMSELVES are still inside their own X.509 validity windows. A CRL
        //     with a fresh nextUpdate can still list (or fail to list, if issued
        //     before expiry) a cert that has since expired on its own clock — the
        //     two checks are independent and both are required. This closes the
        //     gap flagged in docs/bucketB/PARTITION.md (Dev B, TDX): only CRL
        //     freshness was checked before, never the certs' own notBefore/notAfter.
        let now = ASN1Time::from_timestamp(collateral.now_unix).map_err(|_| CertExpired("invalid verifier clock"))?;
        if !leaf.validity().is_valid_at(now) {
            return Err(CertExpired("pck leaf"));
        }
        if !inter.validity().is_valid_at(now) {
            return Err(CertExpired("pck intermediate CA"));
        }
        if !root.validity().is_valid_at(now) {
            return Err(CertExpired("pck root CA"));
        }

        // 4. CRL freshness + revocation (Root CRL revokes the intermediate; PCK
        //    CRL revokes the leaf). Each is optional but recommended.
        check_crl(collateral.root_ca_crl_der.as_ref(), &root, inter.raw_serial(), collateral.now_unix)?;
        check_crl(collateral.pck_crl_der.as_ref(), &inter, leaf.raw_serial(), collateral.now_unix)?;

        // 5. QE-report binding: report_data == SHA-256(att_pub_key ‖ qe_auth).
        let mut h = Sha256::new();
        h.update(sig.att_pub_key);
        h.update(sig.qe_auth);
        let digest = h.finalize();
        let qe_report_data = &sig.qe_report[QE_REPORT_DATA_OFF..QE_REPORT_DATA_OFF + 32];
        if qe_report_data != digest.as_slice() {
            return Err(QeBindingMismatch);
        }

        // 6. The PCK leaf signs the QE report.
        let pck_pub = &leaf.public_key().subject_public_key.data;
        if !ecdsa_p256_verify(pck_pub, sig.qe_report, sig.qe_report_sig) {
            return Err(QeReportSignature);
        }

        // 7. The attestation key signs the quote header ‖ TD body.
        let signed = quote.get(0..QUOTE_SIGNED_LEN).ok_or(MalformedSig("signed region"))?;
        if !ecdsa_p256_verify(sig.att_pub_key, signed, sig.quote_sig) {
            return Err(QuoteSignature);
        }

        // 8. Anti-rollback: TEE_TCB_SVN component-wise >= the floor.
        if let Some(floor) = &collateral.tcb_svn_floor {
            let svn = &quote[HEADER_LEN..HEADER_LEN + TEE_TCB_SVN_LEN];
            if svn.iter().zip(floor.iter()).any(|(got, min)| got < min) {
                return Err(TcbTooLow);
            }
        }

        // 9. Intel TCB-Info + QE-Identity JSON collateral, when supplied (a
        //    `None` waives it, documented — like a `None` CRL). Folds in the TCB
        //    signing chain to the SAME anchored root, both JSON signatures over
        //    their raw signed bodies, `nextUpdate` freshness, the matched TCB
        //    status, and the cross-checks against the quote/PCK. The quote's
        //    `TEE_TCB_SVN` is the first 16 bytes of the TD body.
        if let Some(json) = &collateral.json {
            let tee_tcb_svn = &quote[HEADER_LEN..HEADER_LEN + TEE_TCB_SVN_LEN];
            verify_json_collateral(json, anchor_root_der, collateral.now_unix, &leaf, sig.qe_report, tee_tcb_svn)?;
        }

        Ok(())
    }

    /// The production DCAP entry: verify a TD quote's signature chain against the
    /// **pinned Intel SGX Root CA** ([`PINNED_INTEL_SGX_ROOT_CA_DER`]), which is
    /// now Intel's real, published root (no longer an empty placeholder — see
    /// this module's header correction). A quote whose embedded PCK chain does
    /// not terminate at that exact root is rejected with
    /// [`TdxCollateralError::RootNotAnchored`]; every other named error in
    /// [`TdxCollateralError`] is a hard, fail-closed refusal for its own reason
    /// (expired cert, revoked, bad signature, stale CRL, TCB floor, ...). This
    /// function is UNAUDITED against real hardware — only synthetic vectors
    /// (`tests/tdx_collateral.rs`) have exercised it; see the module header.
    pub fn verify_collateral_dcap(quote: &[u8], collateral: &TdxCollateral) -> Result<(), TdxCollateralError> {
        verify_collateral_anchored(quote, collateral, PINNED_INTEL_SGX_ROOT_CA_DER)
    }

    /// Verify a TD quote end to end **with** Intel PCS/DCAP collateral: the real
    /// chain check ([`verify_collateral_dcap`], pinned Intel root) THEN the
    /// bound-field comparison ([`check_bound_fields`]) — the same
    /// authenticate-then-compare order as SNP. Returns [`crate::Verdict::Genuine`]
    /// only if BOTH pass. This is the ONLY function in this crate that can ever
    /// return `Genuine` for TDX (module-level "RESOLVED" note above) — and on
    /// this host it never has: every quote exercised here is synthetic (its PCK
    /// chain roots at a test CA we minted, not Intel's), so it fails closed at
    /// `RootNotAnchored`, never `Genuine`. Reaching `Genuine` needs a real
    /// Intel-rooted TD quote from TDX hardware we control (hardware-gated).
    pub fn verify_td_quote_with_collateral(
        quote: &[u8],
        expected: &TdxExpected,
        collateral: &TdxCollateral,
    ) -> crate::Verdict {
        let body = match parse_td_quote(quote) {
            Ok(b) => b,
            Err(_) => return crate::Verdict::Unverified("TDX quote is not a well-formed v4 TD 1.0 report"),
        };
        if let Err(e) = verify_collateral_dcap(quote, collateral) {
            // Authenticate first: a collateral failure is fatal, never Genuine.
            return match e {
                TdxCollateralError::PinnedRootUnset => crate::Verdict::Unverified(
                    "TDX pinned Intel SGX Root CA is unset — cannot anchor the chain; failing closed",
                ),
                _ => crate::Verdict::Unverified("TDX collateral chain did not verify — failing closed"),
            };
        }
        // Chain authenticated; now the pinned-field comparison.
        match check_bound_fields(&body, expected) {
            Ok(()) => crate::Verdict::Genuine,
            Err(_) => crate::Verdict::Mismatch("TDX bound field mismatch against the expected genuine TD"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a syntactically valid v4 TDX quote (header + TD 1.0 body) with the
    /// given measured fields. Signature section omitted — the decoder does not
    /// read it, and the chain gate rejects every quote regardless.
    fn synth_quote(mrtd: [u8; 48], mrconfig: [u8; 48], rtmr: [[u8; 48]; 4], report_data: [u8; 64]) -> Vec<u8> {
        let mut q = vec![0u8; MIN_QUOTE_LEN];
        q[OFF_VERSION..OFF_VERSION + 2].copy_from_slice(&QUOTE_VERSION_V4.to_le_bytes());
        q[OFF_TEE_TYPE..OFF_TEE_TYPE + 4].copy_from_slice(&TEE_TYPE_TDX.to_le_bytes());
        let body = HEADER_LEN;
        q[body + B_MRTD..body + B_MRTD + 48].copy_from_slice(&mrtd);
        q[body + B_MRCONFIGID..body + B_MRCONFIGID + 48].copy_from_slice(&mrconfig);
        for (i, r) in rtmr.iter().enumerate() {
            q[body + B_RTMR0 + i * MR_LEN..body + B_RTMR0 + i * MR_LEN + 48].copy_from_slice(r);
        }
        q[body + B_REPORTDATA..body + B_REPORTDATA + 64].copy_from_slice(&report_data);
        q
    }

    fn expected(mrtd: [u8; 48], report_data: [u8; 64]) -> TdxExpected {
        TdxExpected { mrtd, mr_config_id: None, rtmr: None, report_data }
    }

    #[test]
    fn tdx_stub_never_says_genuine() {
        let exp = expected([0; 48], [0; 64]);
        // Even an "everything zero" happy-path input must fail closed.
        assert!(matches!(verify_td_quote(&[], &exp), crate::Verdict::Unverified(_)));
    }

    #[test]
    fn well_formed_full_match_still_fails_closed() {
        // The load-bearing test: a quote whose EVERY pinned field matches the
        // expected values is STILL Unverified, because the collateral chain is
        // unimplemented. TDX must never mint Genuine offline.
        let mrtd = [0x11; 48];
        let cfg = [0x22; 48];
        let rtmr = [[0xA0; 48], [0xA1; 48], [0xA2; 48], [0xA3; 48]];
        let rd = {
            let mut d = [0u8; 64];
            d[..32].copy_from_slice(&[0x33; 32]);
            d
        };
        let q = synth_quote(mrtd, cfg, rtmr, rd);
        let exp = TdxExpected { mrtd, mr_config_id: Some(cfg), rtmr: Some(rtmr), report_data: rd };
        assert!(check_bound_fields(&parse_td_quote(&q).unwrap(), &exp).is_ok(), "fields DO match");
        assert!(
            matches!(verify_td_quote(&q, &exp), crate::Verdict::Unverified(_)),
            "a perfectly matching quote must still fail closed until the chain check lands",
        );
    }

    #[test]
    fn collateral_gate_is_unconditionally_closed() {
        assert!(verify_collateral(&[]).is_err());
        assert!(verify_collateral(&vec![0xFF; MIN_QUOTE_LEN]).is_err());
    }

    #[test]
    fn parse_extracts_fields_at_the_right_offsets() {
        let mrtd = [0x11; 48];
        let cfg = [0x22; 48];
        let rtmr = [[0xB0; 48], [0xB1; 48], [0xB2; 48], [0xB3; 48]];
        let mut rd = [0u8; 64];
        rd[0] = 0xEE;
        let body = parse_td_quote(&synth_quote(mrtd, cfg, rtmr, rd)).unwrap();
        assert_eq!(body.version, QUOTE_VERSION_V4);
        assert_eq!(body.tee_type, TEE_TYPE_TDX);
        assert_eq!(body.mrtd, mrtd);
        assert_eq!(body.mr_config_id, cfg);
        assert_eq!(body.rtmr, rtmr);
        assert_eq!(body.report_data, rd);
    }

    #[test]
    fn parse_rejects_short_wrong_version_and_non_tdx() {
        assert_eq!(parse_td_quote(&[0u8; 10]), Err(TdParseError::TooShort));

        let mut wrong_ver = synth_quote([0; 48], [0; 48], [[0; 48]; 4], [0; 64]);
        wrong_ver[OFF_VERSION..OFF_VERSION + 2].copy_from_slice(&5u16.to_le_bytes());
        assert_eq!(parse_td_quote(&wrong_ver), Err(TdParseError::UnsupportedVersion(5)));

        let mut sgx = synth_quote([0; 48], [0; 48], [[0; 48]; 4], [0; 64]);
        sgx[OFF_TEE_TYPE..OFF_TEE_TYPE + 4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(parse_td_quote(&sgx), Err(TdParseError::NotTdx(0)));
    }

    #[test]
    fn bound_field_mismatches_are_named() {
        let mrtd = [0x11; 48];
        let rd = [0x33; 64];
        let good = synth_quote(mrtd, [0x22; 48], [[0; 48]; 4], rd);
        let body = parse_td_quote(&good).unwrap();

        assert_eq!(check_bound_fields(&body, &expected([0xEE; 48], rd)), Err("mrtd — not the expected genuine TD build measurement"));
        assert_eq!(
            check_bound_fields(&body, &TdxExpected { mrtd, mr_config_id: Some([0xEE; 48]), rtmr: None, report_data: rd }),
            Err("mrconfigid — launch-config binding does not match the audited image"),
        );
        assert_eq!(check_bound_fields(&body, &expected(mrtd, [0xEE; 64])).unwrap_err(), "report_data — nonce/channel binding mismatch (stale, replayed, or relayed quote)");
    }

    #[test]
    fn wrong_rtmr_is_rejected() {
        // A quote's runtime measured-boot registers (RTMR[0..4]) not matching the
        // pinned expected value is a named, fail-closed mismatch — the adversarial
        // "wrong RTMR" vector (rollback / different runtime measurement).
        let mrtd = [0x11; 48];
        let rd = [0x33; 64];
        let good_rtmr = [[0xA0; 48], [0xA1; 48], [0xA2; 48], [0xA3; 48]];
        let wrong_rtmr = [[0xA0; 48], [0xA1; 48], [0xFF; 48], [0xA3; 48]]; // RTMR[2] differs
        let q = synth_quote(mrtd, [0x22; 48], good_rtmr, rd);
        let body = parse_td_quote(&q).unwrap();
        let exp = TdxExpected { mrtd, mr_config_id: None, rtmr: Some(wrong_rtmr), report_data: rd };
        assert_eq!(
            check_bound_fields(&body, &exp),
            Err("rtmr — runtime measured-boot registers do not match"),
        );
        // And the same wrong-RTMR quote must fail closed through the full
        // (still-never-Genuine) offline entry point too.
        let exp_full = TdxExpected { mrtd, mr_config_id: Some([0x22; 48]), rtmr: Some(wrong_rtmr), report_data: rd };
        assert!(matches!(verify_td_quote(&q, &exp_full), crate::Verdict::Unverified(_)));
    }

    #[test]
    fn wrong_mrtd_is_rejected_via_full_entry_point() {
        // A quote whose MRTD (build measurement) does not match, run through the
        // top-level (still fail-closed) entry point — not just check_bound_fields
        // directly. Names the case explicitly for the PARTITION.md negative-vector
        // checklist ("wrong MRTD/RTMR ... FAIL closed").
        let good_mrtd = [0x11; 48];
        let wrong_mrtd = [0x99; 48];
        let rd = [0x33; 64];
        let q = synth_quote(good_mrtd, [0; 48], [[0; 48]; 4], rd);
        let exp = expected(wrong_mrtd, rd);
        assert!(matches!(verify_td_quote(&q, &exp), crate::Verdict::Unverified(_)));
    }

    #[test]
    fn bound_check_uses_the_shared_binding_layout() {
        // report_data must equal binding::report_data(nonce, pubkey) — the same
        // 32-byte-digest-then-zeros layout SNP uses (crate::binding).
        let nonce = [7u8; 32];
        let pubkey = [9u8; 32];
        let rd = binding::report_data(&nonce, &pubkey);
        let mrtd = [0x11; 48];
        let body = parse_td_quote(&synth_quote(mrtd, [0; 48], [[0; 48]; 4], rd)).unwrap();
        assert!(check_bound_fields(&body, &expected(mrtd, rd)).is_ok());
        // verify_td_quote_bound recomputes the same binding, then fails closed.
        assert!(matches!(
            verify_td_quote_bound(&synth_quote(mrtd, [0; 48], [[0; 48]; 4], rd), &nonce, &pubkey, expected(mrtd, [0; 64])),
            crate::Verdict::Unverified(_),
        ));
    }
}
