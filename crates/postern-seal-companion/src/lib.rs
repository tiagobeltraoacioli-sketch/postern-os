//! Postern Seal Companion — the user-facing attestation verifier (a Postern Labs
//! product). Turns the Seal from invisible infrastructure into something a user
//! can *see and use* — the demo of the whole thesis, and the "trust but verify"
//! ethos as a product (verify Postern's claims instead of trusting them).
//!
//! Two modes:
//! - **Self-audit**: does THIS device run the genuine, unmodified build? Compare
//!   the running OS `os_roothash` (dm-verity) to the published attested image,
//!   plus local posture checks (Tor lockdown, no DNS leak, LUKS on).
//! - **Peer-verify**: before trusting ANOTHER Postern device (sending a vault
//!   secret, pairing the wallet, trusting a messenger contact's client), verify
//!   the attestation report it presents — bound to a fresh nonce you issued.
//!
//! This is the verifier half; it mirrors the node's `bloch::attestation` (which
//! *produces* attestations via `getattestation`) and reuses `bloch_crypto::crypto` for
//! the post-quantum signature check.
//!
//! Honest limits & trust model: verification REQUIRES a caller-supplied trust
//! anchor ([`Expected::trusted_pubkey`]) — the expected signer key, obtained out
//! of band (device pairing / QR exchange, or a key published by Postern Labs).
//! Without an anchor the verifier FAILS CLOSED ([`Verdict::Unverified`]): a
//! report checked against the key it carries proves only that *someone* holds a
//! keypair and saw the challenge, so it is never accepted.
//!
//! Two trust-anchor models now coexist, deliberately distinct:
//! - **Pinned device key** (this module): peer-verify between Postern devices,
//!   anchor exchanged out of band.
//! - **Hardware vendor root** (feature `sev-snp`, module [`snp`]): a SEV-SNP
//!   attestation report verified up the VCEK → ASK → ARK chain to AMD's
//!   pinned root — the confidential-VM path (POSTERN-CLOUD.md). TDX is the
//!   documented, fail-closed secondary ([`tdx`]). The channel-binding math
//!   ([`binding`]) and the Seal-gate wire format ([`gate`]) are TEE-independent
//!   and live in the default build.
//!
//! Attestation proves the *build*, not the absence of a kernel 0-day or a
//! coerced user; peer-verify is only sound with a fresh, single-use `challenge`.

use bloch_crypto::crypto;

pub mod binding;
pub mod gate;
pub mod tdx;

/// TPM2 PCR-extend / measured-boot-replay comparison logic — bucket-B/Dev-C's
/// **prep only, no hardware** work for Platform 4 (`docs/bucketB/RUNBOOK.md`).
/// Pure hash-chaining math, tested against a REAL `swtpm` (software TPM
/// emulator, NOT hardware) fixture. Default build (only needs `sha2`, already
/// unconditional here) — read the module docs' HARD HONESTY LABEL before
/// using anything in it.
pub mod tpm2;

#[cfg(feature = "sev-snp")]
pub mod snp;

/// Android Key-Attestation verifier (the `mobile` backend) — parses a
/// StrongBox/TEE Key-Attestation X.509 chain, verifies it to a caller-pinned
/// Google root, and checks nonce / verified-boot / patch-level / app-id.
/// Attests the *phone*, not the workspace. Behind feature `mobile-attest`.
#[cfg(feature = "mobile-attest")]
pub mod mobile;

/// What a Postern device presents to prove it runs the genuine build.
#[derive(Debug, Clone)]
pub struct AttestationReport {
    /// dm-verity roothash of the running OS image (the L1→L3 `os_roothash`).
    pub os_roothash: [u8; 32],
    /// TEE launch measurement (SEV-SNP/TDX), if the device runs in a confidential VM.
    pub measurement: Option<Vec<u8>>,
    /// Echoes the verifier's fresh challenge — binds the report to THIS check
    /// (anti-replay).
    pub nonce: [u8; 32],
    /// The device's attestation public key (hybrid Falcon‖ML-DSA).
    pub pubkey: Vec<u8>,
    /// Signature over `os_roothash ‖ measurement ‖ nonce`.
    pub signature: Vec<u8>,
}

/// The published, expected values for the genuine build + the challenge issued.
#[derive(Debug, Clone)]
pub struct Expected {
    /// The `os_roothash` of the published, reproducible attested image.
    pub os_roothash: [u8; 32],
    /// Require a specific TEE measurement, or `None` to accept a non-TEE device.
    pub measurement: Option<Vec<u8>>,
    /// The single-use nonce the verifier issued for this check.
    pub challenge: [u8; 32],
    /// The trust anchor: the attestation public key the report MUST be signed
    /// by, obtained out of band (device pairing / QR exchange, or a signer key
    /// published by Postern Labs). REQUIRED for any [`Verdict::Genuine`] —
    /// `None` fails closed with [`Verdict::Unverified`], because checking a
    /// report against the key the report itself carries authenticates nothing
    /// (any attacker can self-sign a report echoing public values).
    ///
    /// For TEE-backed devices the state of the art is a chain to the hardware
    /// vendor's root instead of a raw pinned key. That path EXISTS now for
    /// AMD SEV-SNP: enable feature `sev-snp` and use [`crate::snp`], which
    /// verifies the report up the VCEK → ASK → ARK chain to the pinned AMD
    /// root (measurement/HOSTDATA/report_data checked, fail closed). Still
    /// pinned-key-only here: Intel TDX (fail-closed stub, [`crate::tdx`]) and
    /// Android hardware key attestation (chain → Google root) — for those,
    /// and for non-TEE peer devices, the key here IS the root of trust and
    /// must be distributed out of band.
    pub trusted_pubkey: Option<Vec<u8>>,
}

/// The result of verifying an attestation report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every bound field matched AND the signature verified under the
    /// caller-supplied trust anchor. This proves exactly: the holder of the
    /// trusted key signed this (roothash, measurement, nonce) transcript. It is
    /// only as strong as the anchor — today a key pinned out of band, not (yet)
    /// a certificate chain to a hardware vendor root (see
    /// [`Expected::trusted_pubkey`]).
    Genuine,
    /// A specific check failed (which one is named, for an honest UI message).
    Mismatch(&'static str),
    /// No trust anchor was supplied, so nothing in the report can be
    /// authenticated — the verifier fails closed. A self-signed report is
    /// NEVER accepted as genuine.
    Unverified(&'static str),
}

/// The exact bytes an attestation signs: the domain-separated, length-prefixed
/// transcript over the roothash, measurement (if any), and nonce — defined once
/// in `postern-core` so a Postern device producer and this verifier can never
/// disagree, and so the signature can't be replayed as another Postern signature.
fn signed_bytes(r: &AttestationReport) -> Vec<u8> {
    postern_core::seal::attestation_transcript(&r.os_roothash, r.measurement.as_deref(), &r.nonce)
}

/// Verify an attestation report against the expected genuine build.
///
/// FAILS CLOSED without a trust anchor: if `expected.trusted_pubkey` is `None`
/// the only key available is the one the report itself carries, and a signature
/// under an attacker-chosen key authenticates nothing — the verdict is
/// [`Verdict::Unverified`], never [`Verdict::Genuine`].
///
/// Checks, in order: trust anchor present, OS roothash, TEE measurement (if
/// required), nonce freshness, report key equals the anchor, and finally the
/// post-quantum signature over the bound fields — verified against the ANCHOR,
/// not the report's self-declared key.
pub fn verify_report(report: &AttestationReport, expected: &Expected) -> Verdict {
    // Trust anchor first: with no anchor, none of the report's fields are
    // authenticated, so naming a specific mismatch would itself be an overclaim.
    let Some(anchor) = &expected.trusted_pubkey else {
        return Verdict::Unverified(
            "no trust anchor — a report can only be checked against a caller-supplied \
             trusted key; refusing to verify it against its own embedded key",
        );
    };
    if report.os_roothash != expected.os_roothash {
        return Verdict::Mismatch("os_roothash — not the published genuine image");
    }
    if let Some(exp_m) = &expected.measurement {
        match &report.measurement {
            Some(m) if m == exp_m => {}
            _ => return Verdict::Mismatch("tee measurement — not the expected confidential VM"),
        }
    }
    if report.nonce != expected.challenge {
        return Verdict::Mismatch("nonce — stale or replayed report");
    }
    if &report.pubkey != anchor {
        return Verdict::Mismatch("device key — not the pinned/trusted device");
    }
    if !crypto::verify(anchor, &signed_bytes(report), &report.signature) {
        return Verdict::Mismatch("signature — attestation not signed by the trusted key");
    }
    Verdict::Genuine
}

// ── self-audit ───────────────────────────────────────────────────────────────

/// One local posture check (the app supplies the live result: Tor lockdown
/// active, DNS not leaking, LUKS enabled, …).
#[derive(Debug, Clone)]
pub struct AuditItem {
    pub name: String,
    pub pass: bool,
}

/// The self-audit: is this device genuine AND in a good posture? The roothash
/// match gates it; the app fills `items` with the live checks it can run.
#[derive(Debug, Clone, Default)]
pub struct SelfAudit {
    pub roothash_ok: bool,
    pub items: Vec<AuditItem>,
}

impl SelfAudit {
    /// Genuine build AND every posture check passing.
    pub fn is_genuine(&self) -> bool {
        self.roothash_ok && self.items.iter().all(|i| i.pass)
    }
    /// The names of the failing checks (for an honest UI).
    pub fn failures(&self) -> Vec<&str> {
        let mut f = Vec::new();
        if !self.roothash_ok {
            f.push("os_roothash");
        }
        f.extend(self.items.iter().filter(|i| !i.pass).map(|i| i.name.as_str()));
        f
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_report(seed: &[u8], roothash: [u8; 32], nonce: [u8; 32]) -> AttestationReport {
        let (pk, sk) = crypto::generate_keypair_from_seed(seed).unwrap();
        let mut r = AttestationReport {
            os_roothash: roothash,
            measurement: None,
            nonce,
            pubkey: pk,
            signature: vec![],
        };
        r.signature = crypto::sign(&sk, &signed_bytes(&r)).unwrap();
        r
    }

    #[test]
    fn anchored_genuine_report_verifies() {
        let r = signed_report(&[9u8; 32], [1u8; 32], [2u8; 32]);
        let exp = Expected {
            os_roothash: [1u8; 32],
            measurement: None,
            challenge: [2u8; 32],
            trusted_pubkey: Some(r.pubkey.clone()), // anchor = the expected device key
        };
        assert_eq!(verify_report(&r, &exp), Verdict::Genuine);
    }

    #[test]
    fn unanchored_report_is_never_genuine() {
        // The F1 attack: attacker self-signs with their own fresh keypair, copies
        // the published roothash, and echoes the verifier's nonce. With no trust
        // anchor this MUST fail closed — never `Genuine`.
        let r = signed_report(&[7u8; 32], [1u8; 32], [2u8; 32]);
        let exp = Expected { os_roothash: [1u8; 32], measurement: None, challenge: [2u8; 32], trusted_pubkey: None };
        assert!(matches!(verify_report(&r, &exp), Verdict::Unverified(_)));
    }

    #[test]
    fn wrong_signer_is_rejected_despite_valid_self_signature() {
        // Attacker's report is internally consistent (valid signature under its
        // own key), but its key is not the trust anchor.
        let attacker = signed_report(&[7u8; 32], [1u8; 32], [2u8; 32]);
        let (trusted_pk, _) = crypto::generate_keypair_from_seed(&[9u8; 32]).unwrap();
        let exp = Expected {
            os_roothash: [1u8; 32],
            measurement: None,
            challenge: [2u8; 32],
            trusted_pubkey: Some(trusted_pk),
        };
        assert_eq!(
            verify_report(&attacker, &exp),
            Verdict::Mismatch("device key — not the pinned/trusted device")
        );
    }

    #[test]
    fn anchor_key_with_foreign_signature_is_rejected() {
        // Report claims the trusted key but the signature was produced by a
        // different keypair (same transcript, so the foreign signature is a
        // valid signature — just not by the anchor).
        let mut r = signed_report(&[9u8; 32], [1u8; 32], [2u8; 32]);
        let other = signed_report(&[7u8; 32], [1u8; 32], [2u8; 32]);
        r.signature = other.signature;
        let exp = Expected {
            os_roothash: [1u8; 32],
            measurement: None,
            challenge: [2u8; 32],
            trusted_pubkey: Some(r.pubkey.clone()),
        };
        assert_eq!(
            verify_report(&r, &exp),
            Verdict::Mismatch("signature — attestation not signed by the trusted key")
        );
    }

    #[test]
    fn tampered_roothash_is_caught() {
        let r = signed_report(&[9u8; 32], [1u8; 32], [2u8; 32]);
        let exp = Expected {
            os_roothash: [0xEE; 32],
            measurement: None,
            challenge: [2u8; 32],
            trusted_pubkey: Some(r.pubkey.clone()),
        };
        assert!(matches!(verify_report(&r, &exp), Verdict::Mismatch(_)));
    }

    #[test]
    fn replayed_nonce_is_caught() {
        // A report made for an OLD challenge can't satisfy a fresh one, even
        // when it comes from the trusted device key.
        let r = signed_report(&[9u8; 32], [1u8; 32], [0xAA; 32]);
        let exp = Expected {
            os_roothash: [1u8; 32],
            measurement: None,
            challenge: [0xBB; 32],
            trusted_pubkey: Some(r.pubkey.clone()),
        };
        assert_eq!(verify_report(&r, &exp), Verdict::Mismatch("nonce — stale or replayed report"));
    }

    #[test]
    fn forged_signature_is_caught() {
        let mut r = signed_report(&[9u8; 32], [1u8; 32], [2u8; 32]);
        r.signature[0] ^= 0xFF; // corrupt the signature
        let exp = Expected {
            os_roothash: [1u8; 32],
            measurement: None,
            challenge: [2u8; 32],
            trusted_pubkey: Some(r.pubkey.clone()),
        };
        assert!(matches!(verify_report(&r, &exp), Verdict::Mismatch(_)));
    }

    #[test]
    fn unpinned_device_key_rejected_when_pinned() {
        let r = signed_report(&[9u8; 32], [1u8; 32], [2u8; 32]);
        let exp = Expected {
            os_roothash: [1u8; 32],
            measurement: None,
            challenge: [2u8; 32],
            trusted_pubkey: Some(vec![0u8; 8]), // a different, pinned key
        };
        assert_eq!(verify_report(&r, &exp), Verdict::Mismatch("device key — not the pinned/trusted device"));
    }

    #[test]
    fn self_audit_gates_on_roothash_and_posture() {
        let mut a = SelfAudit { roothash_ok: true, items: vec![] };
        a.items.push(AuditItem { name: "tor-lockdown".into(), pass: true });
        a.items.push(AuditItem { name: "dns-leak".into(), pass: true });
        assert!(a.is_genuine());
        a.items.push(AuditItem { name: "luks".into(), pass: false });
        assert!(!a.is_genuine());
        assert_eq!(a.failures(), vec!["luks"]);
    }
}
