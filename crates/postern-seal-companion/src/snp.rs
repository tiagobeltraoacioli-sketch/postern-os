// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs

//! Real AMD SEV-SNP attestation verification — the hardware root of trust
//! that `Expected::trusted_pubkey`'s TODO(attestation-chain) promised.
//!
//! This module has two halves:
//! - the **verifier** (client) side — [`verify_snp_report`] /
//!   [`verify_gate_evidence`] — which authenticates a report up the
//!   VCEK → ASK → ARK chain to the pinned AMD root and compares every expected
//!   field (below);
//! - the **guest** side — [`request_bound_evidence`] / [`request_ext_report`] /
//!   [`request_raw_report`] — which fetches a *live*, channel-bound report from
//!   the AMD Secure Processor via `/dev/sev-guest`. That path is the C2→C3 lift
//!   (POSTERN-CLOUD.md §3; roadmap F3-C3, "vector-tested ≠ attested"): real
//!   ioctl code that only *executes* inside a genuine SEV-SNP confidential VM
//!   and has NOT been run on hardware Postern launched — see
//!   `crates/postern-seal-companion/HARDWARE-RUNBOOK.md`. It is guarded so a
//!   non-TEE host fails closed with a named [`ReportError`], never panics and
//!   never fabricates a report.
//!
//! What [`verify_snp_report`] proves when it returns [`SnpVerdict::Genuine`]:
//! the presented report was signed by an endorsement key whose certificate
//! chains to AMD's published root key (ARK) for the selected EPYC generation —
//! **either** a per-chip **VCEK** (`VCEK → ASK → ARK`) **or** a per-seal
//! **VLEK** (`VLEK → ASVK → ARK`, where the ASVK is AMD's SEV-VLEK signing
//! intermediate). The endorsement type is detected from the certificate's
//! subject CN (`SEV-VCEK` vs `SEV-VLEK`) and the correct pinned intermediate is
//! selected automatically; AWS SEV-SNP guests are endorsed with a VLEK, so the
//! VLEK path is what verifies a real AWS report. **All** trust anchors are
//! *pinned* — the ARK/ASK come compiled-in from `virtee/sev`'s vendored AMD
//! certificates, and the SEV-VLEK ASVK is vendored into this crate from AMD KDS
//! (see `pinned_vlek_ca`); the wire never supplies a root or intermediate.
//! AND the report's
//! launch `measurement`, `HOSTDATA`, `report_data` (channel binding, see
//! [`crate::binding`]) and reported TCB match the caller's expected values,
//! AND the guest policy does not permit debug access, AND the caller's
//! [`RevocationPolicy`] was satisfied — either an out-of-band AMD-KDS CRL shows
//! the VCEK unrevoked, or revocation was *explicitly and loudly* waived. Anything
//! less fails closed with a named [`SnpVerdict::Rejected`] reason.
//!
//! Safe-by-default revocation: the primary [`verify_snp_report`] takes a
//! [`RevocationPolicy`] argument, so a caller who "does nothing special" cannot
//! silently accept a since-revoked VCEK — they must choose between enforcing a
//! CRL ([`RevocationPolicy::Enforce`]) and the loudly-named opt-out
//! ([`RevocationPolicy::SkipRevocationCheckDangerously`], also exposed as
//! [`verify_snp_report_without_revocation`]). This closes the earlier footgun
//! where a plain verify chained to the long-lived pinned roots and returned
//! `Genuine` with no revocation check at all.
//!
//! What it does NOT prove (honest limits):
//! - nothing about *availability* or side channels (POSTERN-CLOUD.md §1.2/§1.3);
//! - revocation is enforced only as strongly as the caller's
//!   [`RevocationPolicy`]. The pinned ARK/ASK are AMD's published 2020-era
//!   long-lived keys and are **UNAUDITED** in this crate; a caller who passes
//!   [`RevocationPolicy::SkipRevocationCheckDangerously`] consciously accepts a
//!   since-revoked VCEK. The CRL itself is fed out of band (this crate does no
//!   network I/O); [`RevocationPolicy::Enforce`] verifies it against the pinned
//!   ASK, enforces its `nextUpdate` freshness, and rejects a revoked serial;
//! - the *expected values themselves* (measurement `M`, policy hash `P`) are
//!   only as good as the release-manifest pipeline that produced them
//!   (POSTERN-CLOUD.md §7). See [`SnpExpected`]'s field docs for exactly how
//!   to derive each one — they are TODO-for-operator (release-manifest /
//!   first-trusted-boot inputs), not code placeholders: the verification gate
//!   itself is fully wired and requires them (there is no way to reach
//!   `Genuine` without supplying real values);
//! - **RESOLVED: certificate temporal validity IS now checked.**
//!   `verify_chain_and_fields` takes a mandatory `now_unix` (seconds since the
//!   Unix epoch, threaded through every public entry point the same way
//!   [`RevocationPolicy`]'s CRL freshness clock is — never an implicit "skip")
//!   and, right after the ARK/ASK/VCEK certs are parsed but before the chain
//!   *signature* is verified, checks each one's X.509 `notBefore`/`notAfter`
//!   window against it (`x509-parser`, the same primitive the AMD-KDS CRL
//!   check below already depends on). A VCEK past its own expiry, or presented
//!   before its validity start, is now a named, fail-closed
//!   [`SnpVerdict::Rejected`] — it can no longer chain and sign successfully
//!   unnoticed. This mirrors [`crate::mobile`]'s `certificate validity` check
//!   exactly (parse → validity window → chain signatures) and closes the SNP
//!   half of the gap this module used to describe; `tdx.rs`'s PCK-chain
//!   analogue (`dcap::verify_collateral_anchored`, feature `tdx-verify`) was
//!   independently confirmed already closed — both TEE backends now enforce
//!   certificate temporal validity, not just AMD-KDS/Intel-PCS CRL freshness.
//!   [`RevocationPolicy::Enforce`]'s CRL freshness check (`nextUpdate`) remains
//!   a *different* thing (revocation-list staleness, not VCEK cert expiry) —
//!   both are required and both now run.
//!
//! Verified offline against a real Milan report + VCEK (`testdata/`, from
//! virtee/sev's Apache-2.0 test fixtures) in `tests/snp_vectors.rs`. NOT yet
//! exercised against a quote produced by hardware we launched — that needs a
//! real SEV-SNP VM (see docs/specs/POSTERN-CLOUD-CONFIDENTIAL.md).

use sev::certs::snp::{builtin, ca, Certificate, Chain, Verifiable};
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::TcbVersion;
use sev::parser::ByteParser;

use crate::binding;
use crate::gate::GateEvidence;

/// Which EPYC generation's pinned AMD root the report must chain to. Selecting
/// the generation is part of `Expected` — a verifier knows what silicon its
/// image was released for (per-shape launch measurements already imply it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmdGeneration {
    /// 3rd-gen EPYC (Azure DCasv5/ECasv5-era SEV-SNP).
    Milan,
    /// 4th-gen EPYC.
    Genoa,
    /// 5th-gen EPYC.
    Turin,
}

/// Minimum acceptable *reported* TCB — the anti-rollback floor (§1.3.2 of
/// POSTERN-CLOUD.md: signature validity alone accepts outdated firmware).
/// Compared component-wise: every component must be ≥ the floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MinTcb {
    /// PSP bootloader SVN floor.
    pub bootloader: u8,
    /// PSP OS SVN floor.
    pub tee: u8,
    /// SNP firmware SVN floor.
    pub snp: u8,
    /// CPU microcode patch-level floor.
    pub microcode: u8,
}

impl MinTcb {
    fn satisfied_by(&self, t: &TcbVersion) -> bool {
        t.bootloader >= self.bootloader
            && t.tee >= self.tee
            && t.snp >= self.snp
            && t.microcode >= self.microcode
    }
}

/// The published, expected values for a genuine Postern Cloud guest — the
/// SEV-SNP analogue of [`crate::Expected`], with the trust anchor supplied by
/// the pinned AMD root instead of an out-of-band device key.
#[derive(Debug, Clone)]
pub struct SnpExpected {
    /// Which pinned AMD root generation the chain must terminate at.
    pub generation: AmdGeneration,
    /// The reference launch measurement `M` for this image + firmware + VM
    /// shape (release manifest, POSTERN-CLOUD.md §7). Always required —
    /// a confidential-VM verifier that doesn't pin the measurement proves
    /// only "some SNP guest somewhere".
    ///
    /// **TODO(operator) — how to fill this in (no code placeholder exists; this
    /// is the real, required struct field and the gate below is fully wired):**
    /// this is the 48-byte SHA-384 launch digest AMD's SNP firmware computes
    /// over the *entire launch sequence* (OVMF/firmware image, then every
    /// `SNP_LAUNCH_UPDATE` page — kernel/initrd/cmdline for direct boot, or the
    /// UKI for a measured-UKI boot — and finally vCPU count/type). It is
    /// deterministic for a given (firmware, image, vCPU shape) tuple and
    /// **specific to that exact shape** — a different vCPU count or firmware
    /// build yields a different `M`, so pin one `SnpExpected::measurement` per
    /// released VM shape, not one globally. Two ways to obtain it, per
    /// HARDWARE-RUNBOOK.md §4:
    /// 1. **Precompute** with AMD's `sev-snp-measure` tool, fed the exact
    ///    OVMF/firmware build, kernel/initrd/cmdline (or UKI) paths, and vCPU
    ///    count/model the release manifest will launch — this is the
    ///    reproducible, auditable path and should run in CI alongside the image
    ///    build so `M` is pinned before any VM launches.
    /// 2. **Read once from a first trusted boot**: launch the exact release
    ///    image, request one report (`request_bound_evidence` /
    ///    `postern-seal-gate`), and copy `report.measurement` verbatim — sound
    ///    only if that first boot is itself trusted (e.g. run under the
    ///    operator's own physical control, or cross-checked against (1)).
    /// The 48 bytes go into this field **byte-for-byte, unmodified** — `M`'s
    /// wire encoding and `sev-snp-measure`'s hex output are the same big-endian
    /// digest, no reordering.
    pub measurement: [u8; 48],
    /// The image-admission policy hash `P` pinned into HOSTDATA at launch
    /// (the L1 binding). `None` only where the provider cannot set HOSTDATA —
    /// then the policy must instead be measured into the boot chain and this
    /// check is consciously waived (document per deployment).
    ///
    /// **TODO(operator):** HOSTDATA is a 32-byte value the *launching party*
    /// (not the silicon) sets at `SNP_LAUNCH_FINISH` time — typically the
    /// release manifest's own hash (`D` or `P` in POSTERN-CLOUD.md §7's
    /// notation: "what admission policy was this guest launched under"). It is
    /// deployment policy, not something derived from the image the way `M` is:
    /// decide what policy hash your launch tooling pins into HOSTDATA (if the
    /// cloud provider's launch API exposes the field at all — some do not,
    /// hence `Option`), record that exact value in the release manifest, and
    /// set `host_data = Some(that value)` here. If the provider cannot set
    /// HOSTDATA, set `None` **and** document in the deployment's own runbook
    /// that the L1 admission-policy binding is carried by the measured boot
    /// chain (`M`) alone, not by HOSTDATA — do not silently drop the guarantee.
    pub host_data: Option<[u8; 32]>,
    /// The exact 64-byte `report_data` required — normally
    /// `binding::report_data(nonce, guest_pubkey)`: freshness + channel
    /// binding in one field. Always required.
    pub report_data: [u8; 64],
    /// Anti-rollback TCB floor (`None` = consciously waived; prefer `Some`).
    ///
    /// **TODO(operator):** this is NOT a fixed constant — it tracks AMD's
    /// evolving microcode/firmware baseline, so a signed release manifest
    /// should carry the current floor and this crate takes it as data rather
    /// than pinning one in code. Derivation (HARDWARE-RUNBOOK.md §4): request
    /// one report from the target platform, read its *reported* TCB
    /// (`bootloader`/`tee`/`snp`/`microcode` — the same four components
    /// [`MinTcb`] compares component-wise), and set the floor **at or below**
    /// that first-observed value — never above (or you reject genuine current
    /// firmware) and never so low that a known-rolled-back component would
    /// still satisfy it (check AMD's SNP firmware/microcode advisories for the
    /// lowest acceptable version per component). Re-derive and re-sign the
    /// floor whenever the fleet's baseline firmware is intentionally upgraded.
    pub min_reported_tcb: Option<MinTcb>,
    /// Required VMPL of the report requester (`Some(0)` for a guest-owned
    /// gate; provider paravisor models may differ — set per deployment).
    pub vmpl: Option<u32>,
}

/// The result of verifying a SEV-SNP report. Reasons are static and specific,
/// for the same honest-UI taxonomy as [`crate::Verdict`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnpVerdict {
    /// Chained to the pinned AMD root AND every expected field matched.
    Genuine,
    /// A named check failed — fail closed, no partial trust.
    Rejected(&'static str),
}

fn pinned_ca(generation: AmdGeneration) -> Option<ca::Chain> {
    // Compiled-in AMD ARK/ASK (virtee/sev vendored copies of AMD's published
    // certificates) — the wire never supplies the root.
    let (ark, ask) = match generation {
        AmdGeneration::Milan => (builtin::milan::ark(), builtin::milan::ask()),
        AmdGeneration::Genoa => (builtin::genoa::ark(), builtin::genoa::ask()),
        AmdGeneration::Turin => (builtin::turin::ark(), builtin::turin::ask()),
    };
    Some(ca::Chain { ark: ark.ok()?, ask: ask.ok()? })
}

// ───────────────────────── VLEK endorsement (the AWS SEV-SNP path) ────────────
//
// AMD endorses an SNP report with one of two keys:
//   * a **VCEK** (Versioned Chip Endorsement Key) — per-chip, derived from the
//     CPU's fused secret; chains VCEK → ASK → ARK. Azure/GCP-style provisioning.
//   * a **VLEK** (Versioned Loaded Endorsement Key) — per-seal, loaded into the
//     PSP by AMD for a cloud tenant; chains VLEK → **ASVK** → ARK, where the
//     ASVK ("AMD SEV-VLEK signing Key", subject CN `SEV-VLEK-<gen>`) is AMD's
//     VLEK-signing intermediate. **AWS SEV-SNP guests are endorsed with a
//     VLEK** — so without this path a genuine AWS report fails the chain step
//     (the VLEK does not chain through the *VCEK* ASK).
//
// The two chains share the SAME ARK root (verified: the KDS VLEK cert_chain's
// ARK is byte-identical to the pinned VCEK ARK for all three generations), so a
// VLEK is verified by building the `sev` crate's generic CA chain with the ASVK
// standing in for the ASK: `ca::Chain { ark, ask: ASVK }` then `Chain { ca, vek:
// VLEK }`. `sev`'s `Chain::verify` already documents this (`ASVK/ARK/VLEK`) and
// its report-signature check pulls the P-384 pubkey straight off the returned
// VEK, so the VLEK signs the report exactly as a VCEK would.
//
// PINNED, VENDORED, OFFLINE: the ASVK is NOT taken from the wire — it is
// vendored into this crate (fetched once at dev time from AMD KDS; provenance
// recorded on each constant below) exactly as the ARK/ASK are pinned via the
// `sev` builtins. Verify does no network I/O.

/// AMD SEV-VLEK signing intermediate (ASVK) for Milan, PEM-encoded.
///
/// Provenance: cert #1 (subject CN `SEV-VLEK-Milan`, issuer `ARK-Milan`) of
/// AMD KDS `https://kdsintf.amd.com/vlek/v1/Milan/cert_chain`, fetched
/// 2026-07-18. Validity 2022-11-16 .. 2047-11-16. Its issuing ARK is
/// byte-identical (SHA-256 fingerprint) to `sev`'s pinned Milan ARK builtin,
/// so a VLEK chained through it terminates at the SAME pinned AMD root as a
/// VCEK. Signature algorithm rsassaPss/SHA-384, as the VCEK ASK.
const VLEK_ASVK_MILAN_PEM: &[u8] = include_bytes!("../vendored-amd-certs/vlek_asvk_milan.pem");

/// AMD SEV-VLEK signing intermediate (ASVK) for Genoa, PEM-encoded.
///
/// Provenance: cert #1 (subject CN `SEV-VLEK-Genoa`) of AMD KDS
/// `https://kdsintf.amd.com/vlek/v1/Genoa/cert_chain`, fetched 2026-07-18. Its
/// issuing ARK matches `sev`'s pinned Genoa ARK builtin (SHA-256 verified).
/// NOTE: not exercised against a real Genoa report in this crate's fixtures —
/// only the Milan VLEK path has a captured-hardware regression test. It is
/// pinned so a Genoa VLEK fleet is covered, anchored to the already-trusted ARK.
const VLEK_ASVK_GENOA_PEM: &[u8] = include_bytes!("../vendored-amd-certs/vlek_asvk_genoa.pem");

/// AMD SEV-VLEK signing intermediate (ASVK) for Turin, PEM-encoded.
///
/// Provenance: cert #1 (subject CN `SEV-VLEK-Turin`) of AMD KDS
/// `https://kdsintf.amd.com/vlek/v1/Turin/cert_chain`, fetched 2026-07-18. Its
/// issuing ARK matches `sev`'s pinned Turin ARK builtin (SHA-256 verified).
/// NOTE: same honesty caveat as Genoa — pinned but not regression-tested
/// against a real Turin report.
const VLEK_ASVK_TURIN_PEM: &[u8] = include_bytes!("../vendored-amd-certs/vlek_asvk_turin.pem");

/// Which endorsement key signed the report, detected from the presented
/// certificate. AWS uses [`EndorsementKind::Vlek`]; Azure/GCP-style chip
/// provisioning uses [`EndorsementKind::Vcek`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndorsementKind {
    /// Per-chip VCEK (subject CN contains `VCEK`): chains VCEK → ASK → ARK.
    Vcek,
    /// Per-seal VLEK (subject CN contains `VLEK`): chains VLEK → ASVK → ARK.
    Vlek,
}

/// Classify an endorsement certificate as a VCEK or a VLEK by its X.509 subject
/// CN (`SEV-VCEK` vs `SEV-VLEK`, per AMD's KDS specs §Chapter 3). Returns `None`
/// for anything that is neither — a fail-closed "unrecognized endorsement" so an
/// attacker cannot smuggle an off-spec cert into either chain. Parses with
/// `x509-parser` (already the CRL/temporal-validity dependency), independent of
/// the `sev` crate.
fn endorsement_kind(der: &[u8]) -> Option<EndorsementKind> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    // A cert may carry more than one CN attribute; accept the first that names a
    // known endorsement key. VLEK first: its issuer/subject both mention VLEK.
    for cn in cert.subject().iter_common_name() {
        let cn = cn.as_str().ok()?;
        if cn.contains("VLEK") {
            return Some(EndorsementKind::Vlek);
        }
        if cn.contains("VCEK") {
            return Some(EndorsementKind::Vcek);
        }
    }
    None
}

/// The pinned CA chain a **VLEK** must terminate through: the same AMD ARK root
/// as the VCEK path, but with the vendored SEV-VLEK ASVK standing in for the ASK
/// (the `sev` crate's `Chain::verify` treats the CA chain's `ask` slot as
/// "whatever intermediate the ARK signs and that signs the VEK", so an ASVK
/// slots in directly). The ARK is the compiled-in `sev` builtin; the ASVK is
/// this crate's vendored, pinned copy — neither is taken from the wire.
fn pinned_vlek_ca(generation: AmdGeneration) -> Option<ca::Chain> {
    let (ark, asvk_pem) = match generation {
        AmdGeneration::Milan => (builtin::milan::ark(), VLEK_ASVK_MILAN_PEM),
        AmdGeneration::Genoa => (builtin::genoa::ark(), VLEK_ASVK_GENOA_PEM),
        AmdGeneration::Turin => (builtin::turin::ark(), VLEK_ASVK_TURIN_PEM),
    };
    let asvk = Certificate::from_pem(asvk_pem).ok()?;
    Some(ca::Chain { ark: ark.ok()?, ask: asvk })
}

/// The pinned CA chain the presented endorsement cert must chain to, chosen by
/// its detected [`EndorsementKind`]. VCEK keeps the exact prior behavior
/// ([`pinned_ca`]); VLEK uses [`pinned_vlek_ca`].
fn pinned_ca_for(kind: EndorsementKind, generation: AmdGeneration) -> Option<ca::Chain> {
    match kind {
        EndorsementKind::Vcek => pinned_ca(generation),
        EndorsementKind::Vlek => pinned_vlek_ca(generation),
    }
}

/// Policy gate, split out so it is unit-testable without a signable report:
/// a guest whose policy allows debug access lets the host read its memory
/// through the SEV-SNP debug interface — never Genuine.
pub(crate) fn policy_forbids_debug(report: &AttestationReport) -> bool {
    !report.policy.debug_allowed()
}

/// Authenticate a report and compare its fields — the chain + field core shared
/// by every public verify entry, WITHOUT the revocation step. Private on
/// purpose: a revocation-unaware verify is precisely the footgun this module
/// closes, so callers always go through [`verify_snp_report`] (which requires a
/// [`RevocationPolicy`]) or its named wrappers.
///
/// `now_unix` (seconds since the Unix epoch) is the verifier's current time,
/// used ONLY for the ARK/ASK/VCEK certificate `notBefore`/`notAfter` window
/// check below — mandatory, like [`RevocationPolicy`]'s CRL freshness clock,
/// so a caller cannot silently skip it by omission.
///
/// Check order: parse every cert, then check certificate temporal validity,
/// THEN authenticate the signature chain (VCEK chain to the pinned root, then
/// the report signature under the VCEK) — mirroring
/// [`crate::mobile::verify_key_attestation_detailed`]'s parse → validity →
/// chain-signature order — and only then compare the now-authenticated
/// fields, so a `Rejected` reason about a field is a statement about what
/// the *silicon signed*, not about attacker-writable bytes.
fn verify_chain_and_fields(report_bytes: &[u8], vcek_der: &[u8], expected: &SnpExpected, now_unix: i64) -> SnpVerdict {
    // 1. Parse. (Variant/generation layout handling is virtee/sev's.)
    let Ok(report) = AttestationReport::from_bytes(report_bytes) else {
        return SnpVerdict::Rejected("report parse — not a well-formed SEV-SNP attestation report");
    };

    // 2. Detect the endorsement type (VCEK vs VLEK) from the presented cert's
    //    subject CN, then select the matching pinned chain: VCEK → ASK → ARK, or
    //    VLEK → ASVK → ARK. AWS SEV-SNP endorses with a VLEK; an unrecognized
    //    cert is a fail-closed "unknown endorsement". The generation's ARK root
    //    is the same for both; only the pinned intermediate differs.
    let Some(kind) = endorsement_kind(vcek_der) else {
        return SnpVerdict::Rejected(
            "endorsement type — certificate is neither a VCEK nor a VLEK (unrecognized subject CN)",
        );
    };
    let Some(ca_chain) = pinned_ca_for(kind, expected.generation) else {
        return SnpVerdict::Rejected("pinned AMD root certificates failed to load");
    };

    // 3. Parse the presented endorsement key (VCEK/VLEK) — untrusted until step
    //    5 chains it to the pinned root.
    let Ok(vcek) = Certificate::from_der(vcek_der) else {
        return SnpVerdict::Rejected("vcek parse — presented endorsement certificate is not valid DER");
    };

    // 4. Certificate temporal validity — ARK, ASK, AND VCEK must each be
    //    inside their own X.509 `notBefore`/`notAfter` window at `now_unix`.
    //    This is independent of, and in addition to, AMD-KDS CRL freshness
    //    (`RevocationPolicy::Enforce`'s `nextUpdate` check, below): a fresh
    //    CRL says nothing about whether the certs THEMSELVES are still inside
    //    their own validity windows (same reasoning as `tdx.rs`'s PCK-chain
    //    check). Re-parses with `x509-parser` (already a dependency for the
    //    CRL path) since the `sev` crate's own `Certificate` type exposes no
    //    validity accessor; the ARK/ASK DER comes from re-encoding the SAME
    //    pinned, compiled-in certs `pinned_ca` just loaded (never the wire).
    let Ok(now) = ASN1Time::from_timestamp(now_unix) else {
        return SnpVerdict::Rejected("verifier clock — now_unix is not a valid timestamp");
    };
    let (Ok(ark_der), Ok(ask_der)) = (ca_chain.ark.to_der(), ca_chain.ask.to_der()) else {
        return SnpVerdict::Rejected("ark/ask der — pinned AMD certificates failed to re-encode for the validity check");
    };
    if !cert_valid_at(&ark_der, now) {
        return SnpVerdict::Rejected("ark validity — pinned AMD ARK root certificate is outside its notBefore/notAfter window");
    }
    if !cert_valid_at(&ask_der, now) {
        return SnpVerdict::Rejected("ask validity — pinned AMD ASK certificate is outside its notBefore/notAfter window");
    }
    if !cert_valid_at(vcek_der, now) {
        return SnpVerdict::Rejected(
            "vcek validity — endorsement certificate is expired or not yet valid (notBefore/notAfter)",
        );
    }

    // 5. ARK self-signature, ARK→(ASK|ASVK), (ASK|ASVK)→(VCEK|VLEK) — the chain
    //    to AMD's root. The `sev` crate's generic `Chain::verify` handles both
    //    (`ca.ask` is the pinned ASK for a VCEK, the pinned ASVK for a VLEK).
    let chain = Chain { ca: ca_chain, vek: vcek };
    if chain.verify().is_err() {
        return SnpVerdict::Rejected(match kind {
            EndorsementKind::Vcek => {
                "vcek chain — endorsement certificate does not chain to the pinned AMD root"
            }
            EndorsementKind::Vlek => {
                "vlek chain — endorsement certificate does not chain to the pinned AMD root"
            }
        });
    }

    // 6. The endorsement key (VCEK/VLEK) must sign this exact report body.
    if (&chain, &report).verify().is_err() {
        return SnpVerdict::Rejected(match kind {
            EndorsementKind::Vcek => "report signature — report is not signed by the chained VCEK",
            EndorsementKind::Vlek => "report signature — report is not signed by the chained VLEK",
        });
    }

    // ── report is now authenticated silicon output; compare fields ──────────

    // 7. Debug policy: a debuggable guest is host-readable.
    if !policy_forbids_debug(&report) {
        return SnpVerdict::Rejected("guest policy — debug access is enabled");
    }

    // 8. Requester VMPL, where the deployment pins one.
    if let Some(vmpl) = expected.vmpl {
        if report.vmpl != vmpl {
            return SnpVerdict::Rejected("vmpl — report requested from an unexpected privilege level");
        }
    }

    // 9. Launch measurement M — the boot chain (firmware + UKI + vCPU state).
    if report.measurement != expected.measurement {
        return SnpVerdict::Rejected("measurement — not the expected genuine image/boot chain");
    }

    // 10. HOSTDATA — the L1 image-admission policy hash P.
    if let Some(host_data) = &expected.host_data {
        if &report.host_data != host_data {
            return SnpVerdict::Rejected("hostdata — launch policy binding does not match the audited image");
        }
    }

    // 11. report_data — freshness (nonce) + channel binding (guest pubkey).
    if report.report_data != expected.report_data {
        return SnpVerdict::Rejected("report_data — nonce/channel binding mismatch (stale, replayed, or relayed report)");
    }

    // 12. Anti-rollback: reported TCB at or above the configured floor.
    if let Some(min) = &expected.min_reported_tcb {
        if !min.satisfied_by(&report.reported_tcb) {
            return SnpVerdict::Rejected("reported tcb — platform firmware below the accepted minimum");
        }
    }

    SnpVerdict::Genuine
}

/// Is `der` (an X.509 certificate) inside its own `notBefore`/`notAfter`
/// window at `now`? A parse failure is treated as invalid (fail closed) —
/// this is only ever called on certs already known to parse (the ARK/ASK are
/// pinned, compiled-in bytes re-encoded via `to_der`; the VCEK was already
/// parsed once by the `sev` crate in step 3 above), so a failure here would
/// mean the two parsers disagree — refuse rather than guess.
fn cert_valid_at(der: &[u8], now: ASN1Time) -> bool {
    match X509Certificate::from_der(der) {
        Ok((_, cert)) => cert.validity().is_valid_at(now),
        Err(_) => false,
    }
}

/// Verify a raw SEV-SNP attestation report against the pinned AMD root, the
/// expected genuine-image values, AND the caller's [`RevocationPolicy`]. Fails
/// closed: any parse error, chain error, field mismatch, or revocation failure
/// is a named [`SnpVerdict::Rejected`].
///
/// The `revocation` argument is mandatory by design — there is no revocation-free
/// short entry, so a caller cannot accept a since-revoked VCEK by simply
/// forgetting to opt in. Choose [`RevocationPolicy::Enforce`] (a fresh AMD-KDS
/// CRL, fetched out of band) for production; the CRL step runs only after the
/// report is otherwise `Genuine`, so a revocation `Rejected` reason always
/// concerns a VCEK that already chained to the pinned AMD root. Waiving the
/// check requires the loud [`RevocationPolicy::SkipRevocationCheckDangerously`]
/// (or [`verify_snp_report_without_revocation`]).
///
/// `now_unix` (seconds since the Unix epoch, the verifier's current time) is
/// likewise mandatory — it is the clock the ARK/ASK/VCEK certificate
/// `notBefore`/`notAfter` window check runs against (see
/// [`verify_chain_and_fields`]); there is no implicit way to skip it, the same
/// safe-by-default discipline as `revocation`.
pub fn verify_snp_report(
    report_bytes: &[u8],
    vcek_der: &[u8],
    expected: &SnpExpected,
    revocation: &RevocationPolicy,
    now_unix: i64,
) -> SnpVerdict {
    match verify_chain_and_fields(report_bytes, vcek_der, expected, now_unix) {
        SnpVerdict::Genuine => enforce_revocation(revocation, expected.generation, vcek_der),
        other => other,
    }
}

/// [`verify_snp_report`] with revocation **explicitly waived** — a loudly-named
/// convenience for [`RevocationPolicy::SkipRevocationCheckDangerously`]. A VCEK
/// that AMD has since revoked WILL be accepted; use only where revocation is
/// enforced by another layer (e.g. short-lived provisioned VCEKs) and say so
/// per deployment. Prefer [`verify_snp_report`] with
/// [`RevocationPolicy::Enforce`].
///
/// `now_unix` is still mandatory — waiving revocation does NOT waive the
/// certificate temporal-validity check (see [`verify_snp_report`]).
pub fn verify_snp_report_without_revocation(
    report_bytes: &[u8],
    vcek_der: &[u8],
    expected: &SnpExpected,
    now_unix: i64,
) -> SnpVerdict {
    verify_snp_report(
        report_bytes,
        vcek_der,
        expected,
        &RevocationPolicy::SkipRevocationCheckDangerously,
        now_unix,
    )
}

/// The full §4.1 client-side step 3, over a decoded gate evidence bundle:
/// recompute the channel binding from OUR nonce and the pubkey the gate
/// presented, then run the complete chain + field + revocation verification. On
/// [`SnpVerdict::Genuine`], the ONLY key it is sound to open the tunnel to is
/// `evidence.guest_pubkey`.
///
/// `expected.report_data` is overwritten with the recomputed binding — the
/// caller supplies measurement/hostdata/TCB policy, never the binding itself.
/// The `revocation` policy is threaded through unchanged, so a gate handshake is
/// as revocation-safe as the caller's chosen policy (no silent CRL-less path).
/// `now_unix` is threaded through unchanged too, for the certificate
/// temporal-validity check (see [`verify_snp_report`]).
pub fn verify_gate_evidence(
    evidence: &GateEvidence,
    nonce: &[u8; 32],
    mut expected: SnpExpected,
    revocation: &RevocationPolicy,
    now_unix: i64,
) -> SnpVerdict {
    expected.report_data = binding::report_data(nonce, &evidence.guest_pubkey);
    verify_snp_report(&evidence.report, &evidence.vcek_der, &expected, revocation, now_unix)
}

// ───────────────────────── AMD-KDS CRL freshness / revocation ─────────────────
//
// Closes the honest gap called out in this module's header: `verify_snp_report`
// chains VCEK → ASK → ARK to the *pinned* AMD root, but the pinned ARK/ASK are
// AMD's long-lived 2020-era keys — so a VCEK that AMD has since **revoked**
// (a decommissioned/compromised chip) still passes the chain check. AMD
// publishes a CRL per product line at
//
//     https://kdsintf.amd.com/vcek/v1/<Milan|Genoa|Turin>/crl
//
// signed by the ASK. This block adds the missing step: fetch that CRL out of
// band (a gate/verifier's provisioning job — this crate does not do network
// I/O), then verify it is (1) signed by the *pinned* ASK, (2) **fresh** — its
// `nextUpdate` has not elapsed, so a stale CRL cannot be replayed to hide a
// fresh revocation — and (3) does not list the presented VCEK's serial.
//
// `SnpExpected` is unchanged (the offline vectors keep their exact struct
// literals). What DID change is the entry point: [`verify_snp_report`] now takes
// a [`RevocationPolicy`], so revocation is part of the default path rather than a
// separate opt-in function a caller can forget. The CRL step still runs only
// after the report is otherwise `Genuine`, so a `Rejected` CRL reason is always a
// statement about an already-authenticated VCEK.

use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::revocation_list::CertificateRevocationList;
use x509_parser::time::ASN1Time;

/// An AMD-KDS certificate revocation list fetched out of band, plus the instant
/// to judge its freshness against. `now_unix` is seconds since the Unix epoch
/// (the verifier's current time) — kept explicit so freshness is testable and
/// the crate stays clock-free.
#[derive(Debug, Clone)]
pub struct KdsCrl {
    /// DER-encoded X.509 CRL as served by AMD KDS (`.../crl`).
    pub crl_der: Vec<u8>,
    /// Verifier's current time, seconds since the Unix epoch, for the
    /// `nextUpdate` freshness comparison.
    pub now_unix: i64,
}

/// How the primary [`verify_snp_report`] treats VCEK **revocation**. There is
/// no implicit "skip" — a caller must name one of these, which is what makes the
/// default path safe: a revoked VCEK can no longer pass by omission.
///
/// The pinned ARK/ASK are AMD's long-lived 2020-era keys and **UNAUDITED** here,
/// so revocation is the only thing standing between a chained-but-decommissioned
/// chip and a `Genuine` verdict.
#[derive(Debug, Clone)]
pub enum RevocationPolicy<'a> {
    /// Enforce revocation with an AMD-KDS CRL fetched out of band, anchored to
    /// the **pinned AMD ASK** for the report's generation (via
    /// [`check_kds_crl`]). The production choice.
    Enforce(&'a KdsCrl),
    /// Enforce revocation with a CRL anchored to an **explicitly supplied**
    /// issuer certificate (DER) instead of the pinned ASK (via
    /// [`check_crl_against_issuer`]). For verifiers that pin a non-KDS issuer
    /// and for offline tests that exercise the real revocation crypto against a
    /// synthetic issuer — production should prefer [`RevocationPolicy::Enforce`].
    EnforceWithIssuer {
        /// The CRL + freshness instant to check.
        crl: &'a KdsCrl,
        /// DER of the issuer certificate whose key signed the CRL.
        issuer_der: &'a [u8],
    },
    /// Revocation is required by policy but **no CRL is available** (e.g. the
    /// out-of-band fetch failed). Fails closed — never `Genuine` — so a missing
    /// CRL cannot silently downgrade to "accept". A caller that genuinely wants
    /// to proceed without revocation must say so with the loud
    /// [`RevocationPolicy::SkipRevocationCheckDangerously`], not this.
    RequireButMissing,
    /// EXPLICIT, LOUD opt-out: skip the revocation check entirely. A VCEK that
    /// AMD has since revoked WILL be accepted. Sound only where revocation is
    /// enforced by another layer (e.g. short-lived provisioned VCEKs) —
    /// document it per deployment.
    SkipRevocationCheckDangerously,
}

/// Why an AMD-KDS CRL could not be honoured. Fail closed: any of these means we
/// cannot assert the VCEK is unrevoked, so the report is not trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrlError {
    /// The pinned AMD ASK for this generation could not be loaded/parsed — with
    /// no trusted issuer the CRL signature cannot be checked.
    PinnedIssuerUnavailable,
    /// The CRL or the VCEK could not be parsed as DER.
    Malformed(&'static str),
    /// The CRL is not signed by the (pinned/supplied) issuer — refuse to trust
    /// an unauthenticated revocation list.
    BadSignature,
    /// The CRL's `nextUpdate` has elapsed relative to `now_unix` (or is absent):
    /// a stale CRL could be replayed to mask a fresh revocation.
    Stale,
    /// The presented VCEK's serial appears on the CRL — the endorsement key is
    /// revoked.
    Revoked,
}

impl core::fmt::Display for CrlError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CrlError::PinnedIssuerUnavailable => {
                write!(f, "pinned AMD ASK unavailable — cannot authenticate the CRL")
            }
            CrlError::Malformed(what) => write!(f, "malformed {what} — cannot establish revocation status"),
            CrlError::BadSignature => write!(f, "CRL is not signed by the pinned AMD ASK"),
            CrlError::Stale => write!(f, "CRL is stale (nextUpdate elapsed) — refresh from AMD KDS"),
            CrlError::Revoked => write!(f, "VCEK serial is listed on the AMD-KDS CRL (revoked)"),
        }
    }
}

impl std::error::Error for CrlError {}

/// DER of the pinned AMD ASK (the CRL's issuer) for a generation — the *same*
/// compiled-in ASK the VCEK chain terminates through, never taken from the wire.
fn pinned_ask_der(generation: AmdGeneration) -> Option<Vec<u8>> {
    let ask = match generation {
        AmdGeneration::Milan => builtin::milan::ask(),
        AmdGeneration::Genoa => builtin::genoa::ask(),
        AmdGeneration::Turin => builtin::turin::ask(),
    };
    ask.ok()?.to_der().ok()
}

/// DER of the pinned AMD SEV-VLEK ASVK for a generation — the issuer of AMD's
/// **VLEK** CRL (`kdsintf.amd.com/vlek/v1/<gen>/crl`), the *same* vendored ASVK
/// the VLEK chain terminates through. Never taken from the wire.
fn pinned_vlek_asvk_der(generation: AmdGeneration) -> Option<Vec<u8>> {
    let pem = match generation {
        AmdGeneration::Milan => VLEK_ASVK_MILAN_PEM,
        AmdGeneration::Genoa => VLEK_ASVK_GENOA_PEM,
        AmdGeneration::Turin => VLEK_ASVK_TURIN_PEM,
    };
    Certificate::from_pem(pem).ok()?.to_der().ok()
}

/// Verify a CRL against an **explicitly supplied issuer certificate** — the
/// mechanism [`check_kds_crl`] is built on. Splitting the issuer out makes the
/// real crypto (CRL signature, `nextUpdate` freshness, serial revocation)
/// exercisable offline against a synthetic issuer in tests; **production callers
/// use [`check_kds_crl`], which pins AMD's ASK.** Supplying a non-AMD issuer
/// here anchors trust to whatever you pass — do that only in tests.
pub fn check_crl_against_issuer(
    crl_der: &[u8],
    issuer_cert_der: &[u8],
    vcek_der: &[u8],
    now_unix: i64,
) -> Result<(), CrlError> {
    let (_, issuer) =
        X509Certificate::from_der(issuer_cert_der).map_err(|_| CrlError::PinnedIssuerUnavailable)?;
    let (_, crl) = CertificateRevocationList::from_der(crl_der).map_err(|_| CrlError::Malformed("crl"))?;

    // 1. Authenticate the CRL against the issuer's public key. An unsigned or
    //    wrongly-signed revocation list proves nothing — refuse it.
    crl.verify_signature(issuer.public_key()).map_err(|_| CrlError::BadSignature)?;

    // 2. Freshness: a CRL past its nextUpdate (or with none) could be replayed
    //    to hide a revocation issued afterwards.
    match crl.next_update() {
        Some(nu) if now_unix <= nu.timestamp() => {}
        _ => return Err(CrlError::Stale),
    }

    // 3. Revocation: is the presented VCEK's serial on the list?
    let (_, vcek) = X509Certificate::from_der(vcek_der).map_err(|_| CrlError::Malformed("vcek"))?;
    let vcek_serial = vcek.raw_serial();
    if crl.iter_revoked_certificates().any(|r| r.raw_serial() == vcek_serial) {
        return Err(CrlError::Revoked);
    }
    Ok(())
}

/// AMD-KDS CRL check anchored to the **pinned issuer** for `generation` and the
/// presented endorsement type: a VCEK's CRL is signed by AMD's ASK, a VLEK's CRL
/// by AMD's SEV-VLEK ASVK (AMD publishes a separate CRL per key type, at
/// `vcek/v1/<gen>/crl` and `vlek/v1/<gen>/crl`). The CRL must be signed by that
/// pinned issuer, be fresh (`nextUpdate` not elapsed), and must not list the
/// presented endorsement cert. The issuer is never taken from the wire. An
/// unrecognized endorsement cert defaults to the VCEK ASK (fail-closed: a
/// mismatched issuer yields [`CrlError::BadSignature`]).
pub fn check_kds_crl(crl: &KdsCrl, generation: AmdGeneration, vcek_der: &[u8]) -> Result<(), CrlError> {
    let issuer_der = match endorsement_kind(vcek_der) {
        Some(EndorsementKind::Vlek) => pinned_vlek_asvk_der(generation),
        _ => pinned_ask_der(generation),
    }
    .ok_or(CrlError::PinnedIssuerUnavailable)?;
    check_crl_against_issuer(&crl.crl_der, &issuer_der, vcek_der, crl.now_unix)
}

/// Apply a [`RevocationPolicy`] to an already chain-and-field-`Genuine` report.
/// Returns [`SnpVerdict::Genuine`] iff the policy is satisfied; every failure is
/// a named fail-closed [`SnpVerdict::Rejected`]. Called only after
/// [`verify_chain_and_fields`] returned `Genuine`, so a `Rejected` here always
/// concerns a VCEK that already chained to the pinned AMD root.
fn enforce_revocation(
    revocation: &RevocationPolicy,
    generation: AmdGeneration,
    vcek_der: &[u8],
) -> SnpVerdict {
    let crl_result = match revocation {
        RevocationPolicy::SkipRevocationCheckDangerously => return SnpVerdict::Genuine,
        RevocationPolicy::RequireButMissing => {
            return SnpVerdict::Rejected(
                "revocation — required but no AMD-KDS CRL supplied; fetch it out of band (fail closed)",
            )
        }
        RevocationPolicy::Enforce(crl) => check_kds_crl(crl, generation, vcek_der),
        RevocationPolicy::EnforceWithIssuer { crl, issuer_der } => {
            check_crl_against_issuer(&crl.crl_der, issuer_der, vcek_der, crl.now_unix)
        }
    };
    match crl_result {
        Ok(()) => SnpVerdict::Genuine,
        Err(CrlError::Revoked) => SnpVerdict::Rejected("kds crl — VCEK is revoked by AMD KDS"),
        Err(CrlError::Stale) => {
            SnpVerdict::Rejected("kds crl — CRL is stale (nextUpdate elapsed); refresh from AMD KDS")
        }
        Err(CrlError::BadSignature) => {
            SnpVerdict::Rejected("kds crl — CRL is not signed by the pinned AMD ASK")
        }
        Err(CrlError::Malformed(_)) => {
            SnpVerdict::Rejected("kds crl — malformed CRL/VCEK; cannot establish revocation status")
        }
        Err(CrlError::PinnedIssuerUnavailable) => {
            SnpVerdict::Rejected("kds crl — pinned AMD ASK unavailable; cannot check revocation")
        }
    }
}

/// [`verify_snp_report`] PLUS the AMD-KDS revocation/freshness gate — a thin
/// convenience for [`RevocationPolicy::Enforce`]. The chain + field verification
/// runs first; only an otherwise-`Genuine` report is then checked against the
/// CRL, so every CRL `Rejected` reason concerns a VCEK that already chained to
/// the pinned AMD root. Any CRL failure fails closed.
///
/// Reuses `crl.now_unix` as the certificate temporal-validity clock too — one
/// verifier wall-clock for both the CRL `nextUpdate` freshness check and the
/// ARK/ASK/VCEK `notBefore`/`notAfter` check, rather than risking two
/// different "now"s disagreeing within a single verification.
pub fn verify_snp_report_with_crl(
    report_bytes: &[u8],
    vcek_der: &[u8],
    expected: &SnpExpected,
    crl: &KdsCrl,
) -> SnpVerdict {
    verify_snp_report(report_bytes, vcek_der, expected, &RevocationPolicy::Enforce(crl), crl.now_unix)
}

// ───────────────────────── guest-side live report acquisition ────────────────
//
// Everything above is the *verifier* (client) half. The block below is the
// *guest* half: fetching a fresh, channel-bound SEV-SNP report from the AMD
// Secure Processor via `/dev/sev-guest`, so a Seal-gate can serve a LIVE quote
// instead of a vendored fixture. This is the C2→C3 lift.
//
// HARDWARE STATUS (say it plainly): this is a reference prototype, UNAUDITED,
// and has NEVER been run on confidential-VM hardware Postern launched. It
// compiles on any Linux target but only *executes* inside a genuine SEV-SNP
// guest. `HARDWARE-RUNBOOK.md` is the procedure to run it on a real AMD Milan
// host and capture the proof. `vector-tested ≠ attested` until then.
//
// Two guards keep a non-TEE host fail-closed — a named error, never a panic,
// never a fabricated report:
//   1. compile-time — the ioctl path is `cfg(target_os = "linux")` because the
//      sev-guest driver is Linux-only and `sev::firmware::guest::Firmware` does
//      not even exist off Linux. Every other target compiles a stub returning
//      `Err(ReportError::UnsupportedPlatform)`.
//   2. run-time — on Linux, opening `/dev/sev-guest` on a box that is not an
//      SEV-SNP guest yields `Err(ReportError::DeviceUnavailable)`; a failing
//      ioctl (unavailable VMPL, PSP error, kernel too old for the extended
//      path) yields `Err(ReportError::ReportRequest)`.
//
// NOTE: this is a library API. The `postern-seal-gate` binary today carries its
// own inline copy of the same ioctl calls; deduping it onto these functions is
// a follow-up for that binary's owner (kept out of scope here on purpose).

/// Why a live report could not be produced. Fail closed: a gate must serve
/// *nothing* rather than serve evidence it cannot stand behind. Reasons are
/// specific for an honest gate log line — the acquisition-side mirror of
/// [`SnpVerdict::Rejected`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportError {
    /// This build target has no SEV-SNP guest interface (non-Linux). The
    /// `/dev/sev-guest` ioctl path exists only on Linux.
    UnsupportedPlatform,
    /// `/dev/sev-guest` could not be opened — this host is almost certainly not
    /// an SEV-SNP confidential VM. Carries the OS error text.
    DeviceUnavailable(String),
    /// The report ioctl itself failed (e.g. an unavailable VMPL, a PSP error,
    /// or a kernel too old for the extended-report path). Carries the reason.
    ReportRequest(String),
    /// A report was produced but no VCEK was available to endorse it: the
    /// hypervisor provisioned no cert table and no VCEK was supplied out of
    /// band. Without a VCEK the client cannot chain to the AMD root, so the
    /// evidence would be unverifiable — refuse to assemble it.
    NoVcek,
}

impl core::fmt::Display for ReportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ReportError::UnsupportedPlatform => write!(
                f,
                "no SEV-SNP guest interface on this platform — /dev/sev-guest is Linux-only; \
                 refusing to fabricate a report (fail closed)"
            ),
            ReportError::DeviceUnavailable(e) => {
                write!(f, "cannot open /dev/sev-guest ({e}) — not an SEV-SNP confidential VM")
            }
            ReportError::ReportRequest(e) => write!(f, "SNP report request failed: {e}"),
            ReportError::NoVcek => write!(
                f,
                "no VCEK available — the hypervisor provisioned no cert table and none was \
                 supplied out of band (fetch it from AMD KDS at provision time)"
            ),
        }
    }
}

impl std::error::Error for ReportError {}

/// Best-effort runtime probe: does this host expose the SEV-SNP guest device?
///
/// `true` is necessary-not-sufficient (the ioctl can still fail — e.g. wrong
/// VMPL); `false` guarantees [`request_ext_report`] / [`request_raw_report`]
/// will fail closed. Always `false` off Linux. Lets a gate log one honest
/// "not a confidential VM" line at startup instead of one per connection.
pub fn sev_guest_device_present() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new("/dev/sev-guest").exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Request a raw SEV-SNP attestation report bound to `report_data`, at the
/// given VMPL (`Some(0)` for a guest-owned gate). No cert table is fetched —
/// use this when the VCEK is provisioned out of band. Fails closed off Linux or
/// off SEV-SNP hardware.
///
/// `report_data` is the 64-byte channel binding; construct it with
/// [`crate::binding::report_data`] so the verifier can recompute and match it.
pub fn request_raw_report(report_data: &[u8; 64], vmpl: Option<u32>) -> Result<Vec<u8>, ReportError> {
    #[cfg(target_os = "linux")]
    {
        use sev::firmware::guest::Firmware;
        let mut fw = Firmware::open().map_err(|e| ReportError::DeviceUnavailable(e.to_string()))?;
        fw.get_report(None, Some(*report_data), vmpl)
            .map_err(|e| ReportError::ReportRequest(e.to_string()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (report_data, vmpl);
        Err(ReportError::UnsupportedPlatform)
    }
}

/// Request an *extended* SEV-SNP report bound to `report_data`: the report plus
/// the VCEK DER from the hypervisor-provisioned cert table, if present
/// (`Ok((report, Some(vcek)))`). `Ok((report, None))` means the host provided
/// no VCEK — the caller must supply one out of band. Fails closed off Linux or
/// off SEV-SNP hardware.
pub fn request_ext_report(
    report_data: &[u8; 64],
    vmpl: Option<u32>,
) -> Result<(Vec<u8>, Option<Vec<u8>>), ReportError> {
    #[cfg(target_os = "linux")]
    {
        use sev::firmware::guest::Firmware;
        use sev::firmware::host::CertType;
        let mut fw = Firmware::open().map_err(|e| ReportError::DeviceUnavailable(e.to_string()))?;
        // VMPL 0 by convention for a guest-owned gate; the extended report also
        // returns the hypervisor cert table (which carries the VCEK).
        let (report, certs) = fw
            .get_ext_report(None, Some(*report_data), vmpl)
            .map_err(|e| ReportError::ReportRequest(e.to_string()))?;
        let vcek = certs
            .unwrap_or_default()
            .into_iter()
            .find(|c| matches!(c.cert_type, CertType::VCEK))
            .map(|c| c.data().to_vec());
        Ok((report, vcek))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (report_data, vmpl);
        Err(ReportError::UnsupportedPlatform)
    }
}

/// Guest-side companion to [`verify_gate_evidence`]: fetch a live, channel-bound
/// report and assemble the [`GateEvidence`] a Seal-gate serves.
///
/// The channel binding is wired in here — the report the silicon signs carries
/// `report_data = SHA-256(nonce ‖ guest_pubkey)` ([`crate::binding`]) — so a
/// verifier recomputing it from *its own* fresh nonce
/// ([`verify_gate_evidence`]) rejects any relayed or replayed report. The VCEK
/// comes from the hypervisor cert table unless `static_vcek` overrides it (an
/// AMD-KDS fetch done at provision time). No VCEK from either source is a
/// fail-closed [`ReportError::NoVcek`] — never emit evidence a client can't
/// chain to the AMD root.
///
/// `vmpl` is the requester privilege level (`Some(0)` for a guest-owned gate).
/// Fails closed off Linux or off SEV-SNP hardware.
pub fn request_bound_evidence(
    nonce: &[u8; 32],
    guest_pubkey: &[u8],
    vmpl: Option<u32>,
    static_vcek: Option<&[u8]>,
) -> Result<GateEvidence, ReportError> {
    let report_data = binding::report_data(nonce, guest_pubkey);
    let (report, table_vcek) = request_ext_report(&report_data, vmpl)?;
    let vcek_der = match static_vcek {
        Some(v) => v.to_vec(),
        None => table_vcek.ok_or(ReportError::NoVcek)?,
    };
    Ok(GateEvidence {
        report,
        vcek_der,
        guest_pubkey: guest_pubkey.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_policy_gate_rejects_debuggable_guests() {
        // The policy check itself, unit-tested directly: a signed report with
        // the debug bit set cannot be minted offline (the bit sits in the
        // silicon-signed region), so the branch is exercised at the helper.
        let mut r = AttestationReport::default();
        assert!(policy_forbids_debug(&r));
        r.policy.set_debug_allowed(true);
        assert!(!policy_forbids_debug(&r));
    }

    // ── offline equivalent of HARDWARE-RUNBOOK.md §7's "debuggable guest
    // policy" negative control, against the REAL captured Milan fixture ───────
    //
    // We cannot mint a validly-SIGNED debug=1 report offline: the policy field
    // sits inside the region the VCEK signs, exactly like measurement/hostdata,
    // so a real hardware run is the only way to see a genuinely-signed debug=1
    // report get rejected by the policy check specifically (see
    // HARDWARE-RUNBOOK.md §7). What IS provable offline, against the real
    // fixture bytes, is the stronger property this module actually relies on:
    // the debug bit cannot be forged post-hoc at all, because flipping it
    // invalidates the VCEK signature before the policy check ever runs (see the
    // check order in `verify_chain_and_fields`: signature, then policy).
    const REPORT_HEX: &str = include_str!("../testdata/report_milan.hex");
    const VCEK_DER: &[u8] = include_bytes!("../testdata/vcek_milan.der");

    /// A verifier clock inside the fixture VCEK's real validity window
    /// (2023-04-03T19:23:43Z .. 2030-04-03T19:23:43Z — `openssl x509 -dates`
    /// against `testdata/vcek_milan.der`), used by every test in this module
    /// that is not specifically exercising the temporal-validity check itself.
    const NOW_IN_WINDOW: i64 = 1_750_000_000; // 2025-06-15

    fn fixture_report_bytes() -> Vec<u8> {
        let s: String = REPORT_HEX.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn fixture_expected_for_debug_bit_test() -> SnpExpected {
        // Only used to reach the debug-policy/signature check; measurement etc.
        // are the fixture's own known-genuine values (see tests/snp_vectors.rs
        // for the full field-comparison vectors).
        fn hex48(s: &str) -> [u8; 48] {
            let mut out = [0u8; 48];
            for (i, b) in out.iter_mut().enumerate() {
                *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
            }
            out
        }
        fn hex64(s: &str) -> [u8; 64] {
            let mut out = [0u8; 64];
            for (i, b) in out.iter_mut().enumerate() {
                *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
            }
            out
        }
        SnpExpected {
            generation: AmdGeneration::Milan,
            measurement: hex48("7a1e5c266c0108dbc9bb94fa926951320940915d0aafb42464bd88b579ea158d3e1a0dc39b2c60bd95b9c480cd81841f"),
            host_data: Some([0u8; 32]),
            report_data: hex64("d447b55d197491bfe15cf298f9de9986b7a7c4be2468b4f6e2d53b71d7c645810b0f2cdfca0040433be063fc1a8293f0f3f8dae7b79fecb3d1cd82bd6a93ebfd"),
            min_reported_tcb: Some(MinTcb { bootloader: 3, tee: 0, snp: 8, microcode: 115 }),
            vmpl: Some(0),
        }
    }

    #[test]
    fn debug_bit_cannot_be_forged_post_hoc_in_a_real_report() {
        // AttestationReport layout (sev crate, #[repr(C)], AMD SNP ABI): version:u32
        // (bytes 0..4), guest_svn:u32 (4..8), policy:GuestPolicy(u64) (8..16, the
        // u64 is 8-byte aligned so it starts exactly at offset 8 with no padding).
        // GuestPolicy's debug_allowed is bit 19 of that u64 (little-endian) =>
        // byte offset 8 + 19/8 = 10, mask 1 << (19 % 8) = 0x08.
        const DEBUG_BIT_BYTE_OFFSET: usize = 10;
        const DEBUG_BIT_MASK: u8 = 0x08;

        let mut report = fixture_report_bytes();

        // Sanity check FIRST: prove the offset/mask actually toggles the parsed
        // debug bit, so this test is provably exercising what it claims to (not
        // just coincidentally landing on "report signature — rejected" for the
        // wrong reason).
        let before = AttestationReport::from_bytes(&report).expect("fixture parses");
        assert!(policy_forbids_debug(&before), "fixture must not be launched with debug allowed");
        report[DEBUG_BIT_BYTE_OFFSET] ^= DEBUG_BIT_MASK;
        let after = AttestationReport::from_bytes(&report).expect("mutated bytes still parse");
        assert!(
            !policy_forbids_debug(&after),
            "byte {DEBUG_BIT_BYTE_OFFSET} / mask {DEBUG_BIT_MASK:#x} did not toggle debug_allowed \
             — the offset assumption in this test is wrong, fix it before trusting the control below"
        );

        // The actual negative control: a report with the debug bit toggled no
        // longer verifies under the VCEK signature (the policy field is inside
        // the signed region), so it can NEVER reach `Genuine` — fail closed.
        assert_eq!(
            verify_snp_report_without_revocation(
                &report,
                VCEK_DER,
                &fixture_expected_for_debug_bit_test(),
                NOW_IN_WINDOW,
            ),
            SnpVerdict::Rejected("report signature — report is not signed by the chained VCEK")
        );
    }

    #[test]
    fn min_tcb_is_component_wise() {
        let floor = MinTcb { bootloader: 3, tee: 0, snp: 8, microcode: 115 };
        let ok = TcbVersion { fmc: None, bootloader: 3, tee: 0, snp: 8, microcode: 115 };
        let newer = TcbVersion { fmc: None, bootloader: 4, tee: 1, snp: 9, microcode: 200 };
        let one_low = TcbVersion { fmc: None, bootloader: 3, tee: 0, snp: 7, microcode: 200 };
        assert!(floor.satisfied_by(&ok));
        assert!(floor.satisfied_by(&newer));
        assert!(!floor.satisfied_by(&one_low), "one stale component must fail the floor");
    }

    // ── guest-side live acquisition: the fail-closed guards ──────────────────
    //
    // The positive path (a real Genuine report minted in-silicon) needs an
    // actual SEV-SNP VM and lives in HARDWARE-RUNBOOK.md. What we CAN prove
    // everywhere is the honest half: on a host that is not a confidential VM,
    // the live path returns a NAMED error and never panics / never fabricates.

    // On a non-Linux target (e.g. the macOS dev host) the ioctl path does not
    // even exist — every acquisition entry point must fail closed at compile
    // time's stub.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_acquisition_fails_closed() {
        let rd = [0u8; 64];
        assert_eq!(request_raw_report(&rd, Some(0)), Err(ReportError::UnsupportedPlatform));
        assert_eq!(request_ext_report(&rd, Some(0)), Err(ReportError::UnsupportedPlatform));
        // Even with a static VCEK supplied it must not shortcut past the guard.
        assert_eq!(
            request_bound_evidence(&[0u8; 32], &[0u8; 32], Some(0), Some(&[0xAB; 1360])),
            Err(ReportError::UnsupportedPlatform)
        );
        assert!(!sev_guest_device_present());
    }

    // On an ordinary Linux host with no /dev/sev-guest, the runtime guard must
    // return DeviceUnavailable — not panic, not fabricate. (Skipped if we are
    // actually running inside an SEV-SNP guest, where the device is present.)
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_non_tee_host_fails_closed() {
        if sev_guest_device_present() {
            return; // real confidential VM — the negative case does not apply
        }
        let rd = [0u8; 64];
        assert!(matches!(request_raw_report(&rd, Some(0)), Err(ReportError::DeviceUnavailable(_))));
        assert!(matches!(request_ext_report(&rd, Some(0)), Err(ReportError::DeviceUnavailable(_))));
        assert!(matches!(
            request_bound_evidence(&[0u8; 32], &[0u8; 32], Some(0), None),
            Err(ReportError::DeviceUnavailable(_))
        ));
    }

    // The report_data a live request binds MUST be exactly the value the
    // verifier recomputes — this pins the guest/verifier wiring agreement
    // independently of any hardware.
    #[test]
    fn bound_evidence_uses_the_same_channel_binding_as_the_verifier() {
        let nonce = [0x11u8; 32];
        let pubkey = [0x22u8; 32];
        // What request_bound_evidence feeds the silicon (its first line):
        let guest_side = binding::report_data(&nonce, &pubkey);
        // What verify_gate_evidence will demand of the report:
        assert!(binding::matches(&guest_side, &nonce, &pubkey));
        // A different pubkey (a MITM's key) would not satisfy the same nonce.
        assert!(!binding::matches(&guest_side, &nonce, &[0x33u8; 32]));
    }

    #[test]
    fn report_error_reasons_are_named() {
        // Each fail-closed reason renders a distinct, non-empty operator line.
        for e in [
            ReportError::UnsupportedPlatform,
            ReportError::DeviceUnavailable("ENOENT".into()),
            ReportError::ReportRequest("VMPL".into()),
            ReportError::NoVcek,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }
}
