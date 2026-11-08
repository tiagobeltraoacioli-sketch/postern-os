// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `terem-gate` audit ledger: one append-only, SHAKE-256 hash-chained
//! trail (over [`postern_trail`], the same primitive
//! `apps/noporis-bridge-glue/src/audit.rs` uses) recording every grant,
//! denial, and revocation -- **never** the bytes/content that crossed. For a
//! `SharedFolder` crossing this means the shared **path string** is logged
//! (it is metadata about what was authorized, not file contents); for
//! `Clipboard`/`Audio` payload bytes never touch this module at all -- there
//! is no payload parameter here to log in the first place.
//!
//! Local device record only. Never telemetry, never leaves the device
//! (`02-security-consent-privacy.md` SS7).

use std::path::Path;

use serde::{Deserialize, Serialize};

use postern_trail::{ChainError, Trail};

use crate::capability::Capability;
use crate::consent_record::GuestInstanceId;
use crate::error::TeremGateError;
use crate::world::World;

/// What happened to one crossing attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateEvent {
    /// The host minted a grant.
    Granted,
    /// A crossing was authorized and allowed to proceed.
    Allowed,
    /// A crossing was refused -- the reason is the honest [`TeremGateError`].
    Denied,
    /// A grant was explicitly revoked (any of the four revocation paths).
    Revoked,
}

/// One trail entry. Flat JSON object (`v`/`prev_hash`/`hash` belong to
/// `postern_trail`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateRecord {
    pub ts: String,
    pub event: GateEvent,
    pub capability: String,
    pub from: String,
    pub to: String,
    pub instance_id: String,
    /// Present only for a `SharedFolder` event -- the authorized path
    /// itself, metadata about the grant, never file contents.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub host_path: Option<String>,
    /// Present only for a `Usb` event.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub usb_device: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
}

fn hex_instance(id: &GuestInstanceId) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// The append-only `terem-gate` audit trail.
pub struct AuditTrail {
    trail: Trail<GateRecord>,
}

impl AuditTrail {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ChainError> {
        Ok(AuditTrail {
            trail: Trail::open(path)?,
        })
    }

    pub fn head(&self) -> &str {
        self.trail.head()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &mut self,
        event: GateEvent,
        capability: Capability,
        from: World,
        to: World,
        instance_id: &GuestInstanceId,
        host_path: Option<&str>,
        usb_device: Option<&str>,
        reason: Option<&TeremGateError>,
        now_iso: impl Into<String>,
    ) -> Result<(), ChainError> {
        self.trail.append(GateRecord {
            ts: now_iso.into(),
            event,
            capability: capability.key().to_string(),
            from: from.label().to_string(),
            to: to.label().to_string(),
            instance_id: hex_instance(instance_id),
            host_path: host_path.map(str::to_string),
            usb_device: usb_device.map(str::to_string),
            reason: reason.map(|e| e.to_string()),
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use postern_trail::verify_chain;
    use tempfile::tempdir;

    #[test]
    fn denied_crossing_is_audited_with_the_honest_reason_never_a_payload() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("terem-gate-audit.jsonl");
        let mut t = AuditTrail::open(&path).unwrap();
        t.record(
            GateEvent::Denied,
            Capability::Clipboard,
            World::Host,
            World::Guest,
            &[0x11; 16],
            None,
            None,
            Some(&TeremGateError::NoRecord),
            "2026-07-12T00:00:00Z",
        )
        .unwrap();
        let n = verify_chain(&path).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn shared_folder_grant_logs_the_path_never_file_contents() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("terem-gate-audit.jsonl");
        let mut t = AuditTrail::open(&path).unwrap();
        t.record(
            GateEvent::Granted,
            Capability::SharedFolder,
            World::Host,
            World::Guest,
            &[0x22; 16],
            Some("/home/operator/Shared"),
            None,
            None,
            "2026-07-12T00:00:01Z",
        )
        .unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("/home/operator/Shared"));
        // The record type has no field capable of carrying file bytes at all.
        assert_eq!(verify_chain(&path).unwrap(), 1);
    }
}
