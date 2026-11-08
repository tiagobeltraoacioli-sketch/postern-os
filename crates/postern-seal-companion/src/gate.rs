//! The Seal-gate wire format — the §4.1 attestation-before-connect handshake
//! (POSTERN-CLOUD.md), transport-agnostic bytes so the same codec serves a
//! plain TCP gate, a Tor onion gate, or a test harness.
//!
//! ```text
//! Client → gate :  "PSG1" ‖ nonce(32)                          (challenge)
//! Gate  → client:  "PSE1" ‖ len(report) u32-le  ‖ report
//!                         ‖ len(vcek)   u32-le  ‖ vcek DER
//!                         ‖ len(pubkey) u32-le  ‖ guest pubkey  (evidence)
//! ```
//!
//! The gate is the ONLY pre-attestation listener on a Postern Cloud guest, so
//! everything here treats its peer as hostile: strict magics, hard per-field
//! size caps (a gate response is ~2.5 KiB in practice), and no allocation
//! before the length check. Nothing in this module *trusts* the evidence —
//! authenticating it is [`crate::snp::verify_snp_report`]'s job; a forged
//! bundle just fails verification there.
//!
//! Default build: pure codec + tests. The `sev-snp` feature adds the end-to-end
//! verifier over this bundle ([`crate::snp::verify_gate_evidence`]).

/// Client challenge magic.
pub const CHALLENGE_MAGIC: &[u8; 4] = b"PSG1";
/// Gate evidence magic.
pub const EVIDENCE_MAGIC: &[u8; 4] = b"PSE1";

/// A full challenge message: magic + fresh 32-byte nonce.
pub const CHALLENGE_LEN: usize = 4 + 32;

/// Hard caps — a real SNP report is 1184/1218 bytes and a VCEK ~1.3 KiB;
/// anything near these caps is already garbage, they only bound allocation.
pub const MAX_REPORT_LEN: usize = 16 * 1024;
/// Cap for the DER-encoded VCEK/VLEK certificate.
pub const MAX_CERT_LEN: usize = 8 * 1024;
/// Cap for the guest public key (a WireGuard key is 32 bytes).
pub const MAX_PUBKEY_LEN: usize = 1024;

/// What the gate presents: the hardware-signed report, the VCEK certificate
/// that (allegedly) signed it, and the guest pubkey the report_data binds.
/// Untrusted until verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateEvidence {
    /// Raw SEV-SNP attestation report bytes (as read from `/dev/sev-guest`).
    pub report: Vec<u8>,
    /// DER-encoded VCEK (or VLEK) certificate for the reporting chip. The
    /// ARK/ASK above it are never taken from the wire — the verifier pins them.
    pub vcek_der: Vec<u8>,
    /// The guest's channel public key (WireGuard) that `report_data` endorses.
    pub guest_pubkey: Vec<u8>,
}

/// Codec errors — every reason named, for an honest gate/client log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Wrong or missing magic bytes.
    BadMagic,
    /// Message shorter than its own length fields promise.
    Truncated,
    /// A declared field length exceeds its hard cap.
    FieldTooLarge(&'static str),
    /// Trailing bytes after the last field (refuse smuggled data).
    TrailingBytes,
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WireError::BadMagic => write!(f, "bad magic — not a Seal-gate message"),
            WireError::Truncated => write!(f, "truncated message"),
            WireError::FieldTooLarge(which) => write!(f, "{which} exceeds its size cap"),
            WireError::TrailingBytes => write!(f, "trailing bytes after the last field"),
        }
    }
}

impl std::error::Error for WireError {}

/// Encode the client challenge.
pub fn encode_challenge(nonce: &[u8; 32]) -> [u8; CHALLENGE_LEN] {
    let mut out = [0u8; CHALLENGE_LEN];
    out[..4].copy_from_slice(CHALLENGE_MAGIC);
    out[4..].copy_from_slice(nonce);
    out
}

/// Decode a client challenge (gate side). Exact length only.
pub fn decode_challenge(msg: &[u8]) -> Result<[u8; 32], WireError> {
    if msg.len() < 4 || &msg[..4] != CHALLENGE_MAGIC {
        return Err(WireError::BadMagic);
    }
    if msg.len() < CHALLENGE_LEN {
        return Err(WireError::Truncated);
    }
    if msg.len() > CHALLENGE_LEN {
        return Err(WireError::TrailingBytes);
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&msg[4..]);
    Ok(nonce)
}

impl GateEvidence {
    /// Encode the evidence bundle (gate side).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 3 * 4 + self.report.len() + self.vcek_der.len() + self.guest_pubkey.len());
        out.extend_from_slice(EVIDENCE_MAGIC);
        for field in [&self.report, &self.vcek_der, &self.guest_pubkey] {
            out.extend_from_slice(&(field.len() as u32).to_le_bytes());
            out.extend_from_slice(field);
        }
        out
    }

    /// Decode an evidence bundle (client side) — caps enforced BEFORE any
    /// field-sized allocation, no trailing bytes tolerated.
    pub fn decode(msg: &[u8]) -> Result<Self, WireError> {
        if msg.len() < 4 || &msg[..4] != EVIDENCE_MAGIC {
            return Err(WireError::BadMagic);
        }
        let mut at = 4usize;
        let mut fields: [Vec<u8>; 3] = [Vec::new(), Vec::new(), Vec::new()];
        for (i, (name, cap)) in [
            ("report", MAX_REPORT_LEN),
            ("vcek certificate", MAX_CERT_LEN),
            ("guest pubkey", MAX_PUBKEY_LEN),
        ]
        .into_iter()
        .enumerate()
        {
            let len_bytes: [u8; 4] = msg
                .get(at..at + 4)
                .ok_or(WireError::Truncated)?
                .try_into()
                .expect("4-byte slice");
            let len = u32::from_le_bytes(len_bytes) as usize;
            if len > cap {
                return Err(WireError::FieldTooLarge(name));
            }
            at += 4;
            let bytes = msg.get(at..at + len).ok_or(WireError::Truncated)?;
            fields[i] = bytes.to_vec();
            at += len;
        }
        if at != msg.len() {
            return Err(WireError::TrailingBytes);
        }
        let [report, vcek_der, guest_pubkey] = fields;
        Ok(GateEvidence { report, vcek_der, guest_pubkey })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> GateEvidence {
        GateEvidence {
            report: vec![0xAB; 1184],
            vcek_der: vec![0xCD; 1360],
            guest_pubkey: vec![0xEF; 32],
        }
    }

    #[test]
    fn challenge_roundtrip() {
        let nonce = [7u8; 32];
        assert_eq!(decode_challenge(&encode_challenge(&nonce)), Ok(nonce));
    }

    #[test]
    fn challenge_rejects_bad_magic_short_and_trailing() {
        assert_eq!(decode_challenge(b"XXXX"), Err(WireError::BadMagic));
        assert_eq!(decode_challenge(&encode_challenge(&[7u8; 32])[..20]), Err(WireError::Truncated));
        let mut long = encode_challenge(&[7u8; 32]).to_vec();
        long.push(0);
        assert_eq!(decode_challenge(&long), Err(WireError::TrailingBytes));
    }

    #[test]
    fn evidence_roundtrip() {
        let e = sample();
        assert_eq!(GateEvidence::decode(&e.encode()), Ok(e));
    }

    #[test]
    fn evidence_rejects_truncation_at_every_boundary() {
        let full = sample().encode();
        // Chop at a spread of points, including inside length prefixes.
        for cut in [0, 3, 4, 5, 7, 8, 100, full.len() - 1] {
            assert!(GateEvidence::decode(&full[..cut]).is_err(), "cut at {cut} must fail");
        }
    }

    #[test]
    fn evidence_rejects_oversized_field_before_allocating() {
        let mut msg = Vec::new();
        msg.extend_from_slice(EVIDENCE_MAGIC);
        // Declared report length = 4 GiB-ish; must be refused by the cap,
        // not attempted.
        msg.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(GateEvidence::decode(&msg), Err(WireError::FieldTooLarge("report")));
    }

    #[test]
    fn evidence_rejects_trailing_bytes() {
        let mut msg = sample().encode();
        msg.push(0x00);
        assert_eq!(GateEvidence::decode(&msg), Err(WireError::TrailingBytes));
    }
}
