// SPDX-License-Identifier: MIT OR Apache-2.0
//! The long-lived [`PairingRecord`] each device persists after a successful,
//! SAS-confirmed ceremony.
//!
//! The record is what lets a device recognise its peer on reconnect **without**
//! re-running the human SAS every time (§2.3): the peer's identity public key is
//! **pinned on first use (TOFU)**, and the channel binding anchors the record to
//! the specific pairing transcript. Re-verification (a fresh SAS) is required
//! only on a fail-closed trigger — an identity-key rotation or a binding change —
//! **never on a timer**.
//!
//! HONEST LIMITS carried by every record:
//! - The pin trusts the device you scanned, not that its software is genuine.
//!   The desktop attests nothing (a software SHA-256 pin is tamper-evidence, not
//!   attestation). A malicious-but-paired desktop is indistinguishable from a
//!   good one.
//! - Unpair/revoke MUST drop the pin and rotate keys (a lost device's pin is a
//!   standing trust root until then). See [`PairingRecord::is_revoked`].
//! - The `session_root` is ephemeral-derived (forward secret) and is NEVER the
//!   wallet seed. It never crosses the wire.

use zeroize::Zeroizing;

use crate::binding::BINDING_LEN;
use crate::hybrid::SESSION_KEY_LEN;

/// Which side of the pair this device is. Custody is asymmetric by design: the
/// phone is the credential (holds the wallet key), the desktop is the terminal
/// (holds nothing).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The phone: strong device, holds the wallet key, verifies.
    Custodian,
    /// The desktop: weak, unattested, software-only terminal; holds nothing.
    Terminal,
}

impl Role {
    /// The peer's role.
    pub fn peer(self) -> Role {
        match self {
            Role::Custodian => Role::Terminal,
            Role::Terminal => Role::Custodian,
        }
    }
}

/// The persisted record of one pairing. Store this sealed at rest
/// (`postern-vault` on desktop, StrongBox/SE-wrapped on mobile — never a
/// plaintext JSON cache).
pub struct PairingRecord {
    /// This device's role in the pair.
    pub role: Role,
    /// A human label for the peer ("Tiago's ThinkPad"). Cosmetic.
    pub nickname: String,
    /// The peer's PINNED long-term identity public key (TOFU). Opaque bytes —
    /// the caller (Dev layer) supplies whatever identity key its wallet/device
    /// layer uses; this crate only pins and compares it.
    pub peer_identity_pub: Vec<u8>,
    /// The channel binding `SHA-256(nonce || anchor_pubkey)` this pairing was
    /// anchored to (mirrors seal-companion). Ties the record to the transcript.
    pub channel_binding: [u8; BINDING_LEN],
    /// The forward-secret session root (ephemeral-derived; NEVER the wallet
    /// seed). Wiped from RAM on drop.
    pub session_root: Zeroizing<[u8; SESSION_KEY_LEN]>,
    /// Revocation flag. Set by an explicit unpair/revoke; a revoked record must
    /// not open a channel.
    revoked: bool,
}

impl PairingRecord {
    pub(crate) fn new(
        role: Role,
        nickname: impl Into<String>,
        peer_identity_pub: Vec<u8>,
        channel_binding: [u8; BINDING_LEN],
        session_root: Zeroizing<[u8; SESSION_KEY_LEN]>,
    ) -> Self {
        PairingRecord {
            role,
            nickname: nickname.into(),
            peer_identity_pub,
            channel_binding,
            session_root,
            revoked: false,
        }
    }

    /// Explicit unpair/revoke: drop trust in this peer. The session root is
    /// wiped and the record refuses to open further channels. Callers should
    /// also delete the persisted copy and rotate any long-term identity keys.
    pub fn revoke(&mut self) {
        self.revoked = true;
        self.session_root = Zeroizing::new([0u8; SESSION_KEY_LEN]);
        self.peer_identity_pub.clear();
    }

    /// Whether this record has been revoked.
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// Fail-closed reconnect check: does a presented peer identity key match the
    /// pinned one? A mismatch (key rotation / substitution) MUST trigger a fresh
    /// SAS ceremony, never a silent re-pair.
    pub fn peer_matches(&self, presented_identity_pub: &[u8]) -> bool {
        !self.revoked
            && !self.peer_identity_pub.is_empty()
            && self.peer_identity_pub == presented_identity_pub
    }
}

impl core::fmt::Debug for PairingRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PairingRecord")
            .field("role", &self.role)
            .field("nickname", &self.nickname)
            .field("peer_identity_pub_len", &self.peer_identity_pub.len())
            .field("revoked", &self.revoked)
            // session_root deliberately omitted.
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec() -> PairingRecord {
        PairingRecord::new(
            Role::Terminal,
            "Tiago's ThinkPad",
            vec![1, 2, 3, 4],
            [9u8; BINDING_LEN],
            Zeroizing::new([5u8; SESSION_KEY_LEN]),
        )
    }

    #[test]
    fn peer_matches_pinned_key() {
        let r = rec();
        assert!(r.peer_matches(&[1, 2, 3, 4]));
        assert!(!r.peer_matches(&[1, 2, 3, 5]));
    }

    #[test]
    fn revoke_drops_trust() {
        let mut r = rec();
        r.revoke();
        assert!(r.is_revoked());
        assert!(!r.peer_matches(&[1, 2, 3, 4]));
        assert_eq!(&*r.session_root, &[0u8; SESSION_KEY_LEN]);
    }

    #[test]
    fn roles_are_opposite() {
        assert_eq!(Role::Custodian.peer(), Role::Terminal);
        assert_eq!(Role::Terminal.peer(), Role::Custodian);
    }
}
