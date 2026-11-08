// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
//! Bloch device verification — fail-closed. **Business/Enterprise edition only.**
//! Pre-release and **UNAUDITED**.
//!
//! The transport (`crates/postern-messenger`) states the honest gap: device
//! verification (SAS) is not yet part of room classification. This crate is the
//! app-layer answer — the trust STATE MACHINE for a peer device's E2EE identity
//! key, plus a REFERENCE short-authentication-string derivation. It binds to the
//! [`postern_messenger::SecurityTier`] wall (verification only makes sense for
//! the internal E2EE tier) and does NOT reimplement the real Matrix
//! `m.key.verification.*` protocol / cross-signing.
//!
//! Fail-closed, always:
//! - Every device starts [`Trust::Unverified`]. Unverified is a FLAG, not trust.
//! - [`DeviceRegistry::is_trusted`] is true ONLY for an explicitly verified device.
//! - A fingerprint / SAS mismatch → [`Trust::Blocked`] (a possible MITM).
//! - An identity-key CHANGE on a verified device → re-flagged Unverified (TOFU
//!   break), never auto-re-trusted.
//! - [`DeviceRegistry::guard_send`] refuses toward any non-verified device.
//!
//! The JS/ESM module in `../device-verification.mjs` is the app's primary
//! implementation; this Rust core demonstrates the same fail-closed rail.

use std::collections::BTreeMap;

use postern_messenger::SecurityTier;
use sha2::{Digest, Sha256};

/// Trust state of a peer device. `Unverified` is the fail-closed default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// Default. Identity key seen but NOT confirmed — flagged, never trusted.
    Unverified,
    /// The user confirmed the identity key out-of-band or via SAS.
    Verified,
    /// A fingerprint / SAS MISMATCH — actively distrusted (suspected MITM).
    Blocked,
}

impl Trust {
    /// Honest badge — an unverified device is never rendered as safe.
    pub const fn badge(self) -> &'static str {
        match self {
            Trust::Verified => "\u{2705} Verified device",
            Trust::Blocked => "\u{26d4} Verification FAILED — do not trust this device",
            Trust::Unverified => "\u{26a0} Unverified device — identity not confirmed",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("unknown device \"{0}\" — observe() it before verifying")]
    UnknownDevice(String),
    #[error(
        "device \"{0}\" is {1:?} — refusing to send toward an unverified device (Bloch fails closed)"
    )]
    Unverified(String, Trust),
    #[error(
        "verification only applies to internal E2EE conversations, not {0:?} (bridged is disclosed, never verified as internal)"
    )]
    NotInternal(SecurityTier),
}

/// Normalize an identity-key fingerprint for a stable compare.
fn norm(fp: &str) -> String {
    fp.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase()
}

#[derive(Debug, Clone)]
struct DeviceState {
    fingerprint: String,
    owner: Option<String>,
    trust: Trust,
    method: Option<&'static str>,
    key_changed: bool,
}

/// The app's source of truth for which peer devices are trusted. Fail-closed.
#[derive(Debug, Default)]
pub struct DeviceRegistry {
    devices: BTreeMap<String, DeviceState>,
}

impl DeviceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or re-observe) a peer device + its identity key. New devices are
    /// Unverified. A KNOWN device presenting a DIFFERENT key is a TOFU break:
    /// re-flagged Unverified (never auto-trusted).
    pub fn observe(&mut self, device_id: &str, identity_key: &str, owner: Option<&str>) -> Trust {
        let fp = norm(identity_key);
        match self.devices.get_mut(device_id) {
            Some(d) if d.fingerprint != fp => {
                d.fingerprint = fp;
                d.trust = Trust::Unverified;
                d.method = None;
                d.key_changed = true;
            }
            Some(d) => {
                if let Some(o) = owner {
                    d.owner = Some(o.to_string());
                }
            }
            None => {
                self.devices.insert(
                    device_id.to_string(),
                    DeviceState {
                        fingerprint: fp,
                        owner: owner.map(str::to_string),
                        trust: Trust::Unverified,
                        method: None,
                        key_changed: false,
                    },
                );
            }
        }
        self.trust(device_id)
    }

    /// Current trust (fail-closed: an unknown device is Unverified).
    pub fn trust(&self, device_id: &str) -> Trust {
        self.devices.get(device_id).map(|d| d.trust).unwrap_or(Trust::Unverified)
    }

    /// The one predicate callers gate on. True ONLY for a Verified device.
    pub fn is_trusted(&self, device_id: &str) -> bool {
        matches!(self.devices.get(device_id).map(|d| d.trust), Some(Trust::Verified))
    }

    /// Out-of-band verify: exact fingerprint match → Verified; else Blocked.
    pub fn verify_out_of_band(
        &mut self,
        device_id: &str,
        presented: &str,
    ) -> Result<Trust, VerifyError> {
        let d = self
            .devices
            .get_mut(device_id)
            .ok_or_else(|| VerifyError::UnknownDevice(device_id.to_string()))?;
        if norm(presented) == d.fingerprint {
            d.trust = Trust::Verified;
            d.method = Some("out-of-band");
            d.key_changed = false;
        } else {
            d.trust = Trust::Blocked;
            d.method = Some("out-of-band");
        }
        Ok(d.trust)
    }

    /// Begin a SAS: derive the short authentication string BOTH sides compute
    /// from the two fingerprints + a shared transcript salt. Reference only (a
    /// transcript hash, not the audited ECDH-based m.key.verification.sas).
    pub fn begin_sas(&self, device_id: &str, my_fingerprint: &str, transcript: &str) -> Result<Sas, VerifyError> {
        let d = self
            .devices
            .get(device_id)
            .ok_or_else(|| VerifyError::UnknownDevice(device_id.to_string()))?;
        let mut pair = [norm(my_fingerprint), d.fingerprint.clone()];
        pair.sort(); // order-independent: both sides derive the same SAS
        let material = format!("bloch-sas/v1|{}|{}|{}", transcript, pair[0], pair[1]);
        let digest = Sha256::digest(material.as_bytes());
        Ok(Sas::from_bytes(&digest))
    }

    /// Finish a SAS. `matched` is the users' explicit "identical on both screens"
    /// decision. true → Verified; false → Blocked (fail-closed).
    pub fn confirm_sas(&mut self, device_id: &str, matched: bool) -> Result<Trust, VerifyError> {
        let d = self
            .devices
            .get_mut(device_id)
            .ok_or_else(|| VerifyError::UnknownDevice(device_id.to_string()))?;
        if matched {
            d.trust = Trust::Verified;
            d.method = Some("sas");
            d.key_changed = false;
        } else {
            d.trust = Trust::Blocked;
            d.method = Some("sas");
        }
        Ok(d.trust)
    }

    /// Fail-closed send guard. `tier` must be the internal E2EE tier (bridged is
    /// disclosed, never "verified"). Errors unless the device is Verified.
    pub fn guard_send(&self, device_id: &str, tier: SecurityTier) -> Result<(), VerifyError> {
        if tier != SecurityTier::InternalE2ee {
            return Err(VerifyError::NotInternal(tier));
        }
        if self.is_trusted(device_id) {
            Ok(())
        } else {
            Err(VerifyError::Unverified(device_id.to_string(), self.trust(device_id)))
        }
    }

    /// Devices that are NOT verified — what a security-review panel must surface.
    pub fn unverified(&self) -> Vec<String> {
        self.devices
            .iter()
            .filter(|(_, d)| d.trust != Trust::Verified)
            .map(|(id, _)| id.clone())
            .collect()
    }
}

/// A reference short authentication string: 7 emoji + three decimals, Matrix-style.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sas {
    /// Indices into the 64-emoji Matrix SAS table (rendering is the UI's job).
    pub emoji_indices: [u8; 7],
    /// Three 4-digit decimals (Matrix decimal SAS).
    pub decimal: [u16; 3],
}

impl Sas {
    fn from_bytes(bytes: &[u8]) -> Self {
        // 7 emoji * 6 bits = 42 bits -> 6 bytes.
        let mut bits: u64 = 0;
        for &b in bytes.iter().take(6) {
            bits = (bits << 8) | b as u64;
        }
        let mut emoji_indices = [0u8; 7];
        for (i, slot) in emoji_indices.iter_mut().enumerate() {
            let shift = 42 - 6 * (i as u32 + 1);
            *slot = ((bits >> shift) & 0x3f) as u8;
        }
        // 3 decimals * 13 bits = 39 bits -> 5 bytes.
        let mut dbits: u64 = 0;
        for &b in bytes.iter().take(5) {
            dbits = (dbits << 8) | b as u64;
        }
        let mut decimal = [0u16; 3];
        for (i, slot) in decimal.iter_mut().enumerate() {
            let shift = 40 - 13 * (i as u32 + 1);
            *slot = (((dbits >> shift) & 0x1fff) as u16) + 1000;
        }
        Sas { emoji_indices, decimal }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unverified_by_default_and_fail_closed() {
        let mut reg = DeviceRegistry::new();
        // Unknown device: fail-closed.
        assert!(!reg.is_trusted("dev-x"));
        assert!(reg
            .guard_send("dev-x", SecurityTier::InternalE2ee)
            .is_err());

        reg.observe("dev-ana", "ED AAAA bbbb", Some("Ana"));
        assert_eq!(reg.trust("dev-ana"), Trust::Unverified);
        // Observing does NOT trust; guard still refuses.
        assert!(reg.guard_send("dev-ana", SecurityTier::InternalE2ee).is_err());
    }

    #[test]
    fn out_of_band_match_verifies_mismatch_blocks() {
        let mut reg = DeviceRegistry::new();
        reg.observe("dev-ana", "ED-AAAA", None);
        // Whitespace/case-insensitive exact compare verifies.
        assert_eq!(reg.verify_out_of_band("dev-ana", " ed-aaaa ").unwrap(), Trust::Verified);
        assert!(reg.is_trusted("dev-ana"));
        assert!(reg.guard_send("dev-ana", SecurityTier::InternalE2ee).is_ok());

        reg.observe("dev-bruno", "ED-BBBB", None);
        assert_eq!(reg.verify_out_of_band("dev-bruno", "ED-WRONG").unwrap(), Trust::Blocked);
        assert!(!reg.is_trusted("dev-bruno"));
    }

    #[test]
    fn sas_is_order_independent_and_confirm_gates_trust() {
        let mut a = DeviceRegistry::new();
        a.observe("peer", "ED-PEER", None);
        // Both sides derive the SAME SAS regardless of who is "self".
        let s1 = a.begin_sas("peer", "ED-SELF", "attempt-1").unwrap();

        let mut b = DeviceRegistry::new();
        b.observe("peer", "ED-SELF", None);
        let s2 = b.begin_sas("peer", "ED-PEER", "attempt-1").unwrap();
        assert_eq!(s1, s2, "SAS is order-independent");

        // Users say "no match" -> Blocked (fail-closed), not a silent retry.
        assert_eq!(a.confirm_sas("peer", false).unwrap(), Trust::Blocked);
        assert!(!a.is_trusted("peer"));
        // A fresh attempt that matches -> Verified.
        a.observe("peer2", "ED-PEER", None);
        assert_eq!(a.confirm_sas("peer2", true).unwrap(), Trust::Verified);
    }

    #[test]
    fn key_change_on_verified_device_re_flags_unverified() {
        let mut reg = DeviceRegistry::new();
        reg.observe("dev-ana", "ED-AAAA", None);
        reg.verify_out_of_band("dev-ana", "ED-AAAA").unwrap();
        assert!(reg.is_trusted("dev-ana"));
        // Identity key changes under us (TOFU break) -> distrust until re-verified.
        reg.observe("dev-ana", "ED-CCCC", None);
        assert_eq!(reg.trust("dev-ana"), Trust::Unverified);
        assert!(!reg.is_trusted("dev-ana"));
    }

    #[test]
    fn bridged_conversations_are_never_verified_as_internal() {
        let mut reg = DeviceRegistry::new();
        reg.observe("dev-ana", "ED-AAAA", None);
        reg.verify_out_of_band("dev-ana", "ED-AAAA").unwrap();
        // Even a verified device cannot "send" on a bridged (non-internal) tier.
        assert!(matches!(
            reg.guard_send("dev-ana", SecurityTier::BridgedExternal),
            Err(VerifyError::NotInternal(SecurityTier::BridgedExternal))
        ));
    }
}
