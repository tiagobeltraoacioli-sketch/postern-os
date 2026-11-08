//! Channel binding for attestation-before-connect (POSTERN-CLOUD.md §4.1).
//!
//! The Seal-gate handshake binds the attestation to the *specific channel* the
//! client is about to open: the guest requests its SEV-SNP report (TDX: TD
//! quote) with
//!
//! ```text
//! report_data = SHA-256(nonce ‖ guest_public_key) ‖ 0x00 × 32
//! ```
//!
//! where `nonce` is the verifier's fresh 32-byte challenge and
//! `guest_public_key` is the guest's WireGuard public key, generated *inside*
//! the guest. Because `report_data` sits in the hardware-signed report body:
//!
//! - the **nonce** gives freshness — a replayed report fails the recompute;
//! - the **pubkey** gives the binding — a man-in-the-middle relaying a valid
//!   quote from a real CVM cannot terminate the tunnel itself, because the key
//!   the client tunnels to is the key the silicon endorsed.
//!
//! SEV-SNP `REPORT_DATA` (and the TDX quote's `report_data`) is 64 bytes; we
//! use the first 32 for the SHA-256 digest and zero-fill the rest, so the same
//! layout works for both TEEs. The concatenation is injective because the
//! nonce length is fixed (32 bytes).
//!
//! This module is TEE-independent math, built and tested in the DEFAULT build;
//! the hardware-signed context around it is the `sev-snp` feature ([`crate::snp`]).

use sha2::{Digest, Sha256};

/// Size of the `report_data` field in a SEV-SNP report / TDX quote.
pub const REPORT_DATA_LEN: usize = 64;

/// Compute the 64-byte `report_data` a genuine gate must have requested:
/// `SHA-256(nonce ‖ guest_pubkey)` in bytes 0..32, zeros in bytes 32..64.
///
/// Guest side: call this before requesting the report from `/dev/sev-guest`.
/// Verifier side: recompute it from your own nonce and the pubkey the gate
/// presented, then require the report's `report_data` to match exactly.
pub fn report_data(nonce: &[u8; 32], guest_pubkey: &[u8]) -> [u8; REPORT_DATA_LEN] {
    let mut h = Sha256::new();
    h.update(nonce);
    h.update(guest_pubkey);
    let digest = h.finalize();
    let mut out = [0u8; REPORT_DATA_LEN];
    out[..32].copy_from_slice(&digest);
    out
}

/// Verifier-side check: does the report's `report_data` equal the binding of
/// OUR nonce to the pubkey the gate presented? All inputs are public values —
/// this is an integrity comparison, not a secret comparison, so a plain
/// equality is sound.
pub fn matches(report_data_field: &[u8; REPORT_DATA_LEN], nonce: &[u8; 32], guest_pubkey: &[u8]) -> bool {
    report_data_field == &report_data(nonce, guest_pubkey)
}

/// Named-error verifier entry point: the recompute-not-trust helper the
/// transport test and a real gate both call.
///
/// Unlike [`matches`], this returns a *named* [`Result`] so the caller can log
/// exactly why a channel binding was rejected and so a `?`-driven gate fails
/// closed. It recomputes `report_data` from the **verifier's own** `nonce` and
/// the `guest_pubkey` the gate presented — never trusting any value the peer
/// supplied — and accepts only on an exact, whole-field match.
///
/// The 64-byte layout is enforced explicitly:
///
/// - bytes `32..64` must be zero-filled (any non-zero tail is rejected before
///   the digest is even compared, so a report that smuggles data past the
///   SHA-256 half is refused regardless of the digest);
/// - bytes `0..32` must equal `SHA-256(nonce ‖ guest_pubkey)`.
///
/// # Errors
///
/// - `"report_data tail (bytes 32..64) must be zero-filled"` — the reserved
///   tail carried non-zero bytes.
/// - `"report_data does not bind this nonce and pubkey"` — the digest half did
///   not match the verifier's recomputation (substituted pubkey, stale/replayed
///   nonce, or otherwise tampered digest).
pub fn verify_channel_binding(
    report_data_field: &[u8; REPORT_DATA_LEN],
    nonce: &[u8; 32],
    guest_pubkey: &[u8],
) -> Result<(), &'static str> {
    // Fail closed on any non-zero reserved tail first: the tail is not part of
    // the digest, so a lax verifier could otherwise let a peer stash bytes there.
    if report_data_field[32..] != [0u8; REPORT_DATA_LEN - 32] {
        return Err("report_data tail (bytes 32..64) must be zero-filled");
    }
    let expected = report_data(nonce, guest_pubkey);
    // Whole-field equality (tail already checked, but keep the comparison total).
    if report_data_field == &expected {
        Ok(())
    } else {
        Err("report_data does not bind this nonce and pubkey")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce() -> [u8; 32] {
        core::array::from_fn(|i| i as u8) // 00 01 … 1f
    }
    fn pubkey() -> [u8; 32] {
        core::array::from_fn(|i| 0x80 + i as u8) // 80 81 … 9f
    }

    #[test]
    fn known_answer_vector() {
        // SHA-256(00…1f ‖ 80…9f), independently computed (python hashlib):
        let expect_hash = "692ad7b1734f469491cd141294700a02130a37b7faef4211a272327387360f67";
        let rd = report_data(&nonce(), &pubkey());
        let got: String = rd[..32].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, expect_hash);
        assert_eq!(&rd[32..], &[0u8; 32], "tail must be zero-filled");
    }

    #[test]
    fn binding_matches_itself() {
        let rd = report_data(&nonce(), &pubkey());
        assert!(matches(&rd, &nonce(), &pubkey()));
    }

    #[test]
    fn stale_nonce_fails_binding() {
        // Relay/replay: a report bound to an OLD nonce never satisfies a fresh one.
        let rd = report_data(&[0xAA; 32], &pubkey());
        assert!(!matches(&rd, &nonce(), &pubkey()));
    }

    #[test]
    fn substituted_pubkey_fails_binding() {
        // MITM splice: same fresh nonce, but the attacker presents THEIR key —
        // the silicon-endorsed report_data no longer matches.
        let rd = report_data(&nonce(), &pubkey());
        assert!(!matches(&rd, &nonce(), &[0x42u8; 32]));
    }

    #[test]
    fn verify_accepts_bound_key() {
        let rd = report_data(&nonce(), &pubkey());
        assert_eq!(verify_channel_binding(&rd, &nonce(), &pubkey()), Ok(()));
    }

    #[test]
    fn verify_rejects_substituted_pubkey() {
        // MITM splice: fresh nonce, attacker's key — digest half no longer matches.
        let rd = report_data(&nonce(), &pubkey());
        assert_eq!(
            verify_channel_binding(&rd, &nonce(), &[0x42u8; 32]),
            Err("report_data does not bind this nonce and pubkey")
        );
    }

    #[test]
    fn verify_rejects_stale_nonce() {
        // Replay: a report bound to an OLD nonce never satisfies the fresh one.
        let rd = report_data(&[0xAA; 32], &pubkey());
        assert_eq!(
            verify_channel_binding(&rd, &nonce(), &pubkey()),
            Err("report_data does not bind this nonce and pubkey")
        );
    }

    #[test]
    fn verify_rejects_nonzero_tail() {
        // Correct digest half, but a smuggled non-zero reserved tail must fail.
        let mut rd = report_data(&nonce(), &pubkey());
        rd[63] = 0x01;
        assert_eq!(
            verify_channel_binding(&rd, &nonce(), &pubkey()),
            Err("report_data tail (bytes 32..64) must be zero-filled")
        );
        // A non-zero byte anywhere in 32..64, not just the last, is rejected.
        let mut rd2 = report_data(&nonce(), &pubkey());
        rd2[32] = 0xFF;
        assert_eq!(
            verify_channel_binding(&rd2, &nonce(), &pubkey()),
            Err("report_data tail (bytes 32..64) must be zero-filled")
        );
    }

    #[test]
    fn distinct_inputs_distinct_bindings() {
        // Injectivity smoke test (fixed-length nonce makes ‖ unambiguous).
        let a = report_data(&nonce(), &pubkey());
        let mut n2 = nonce();
        n2[31] ^= 1;
        assert_ne!(a, report_data(&n2, &pubkey()));
    }
}
