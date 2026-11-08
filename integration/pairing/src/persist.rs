// SPDX-License-Identifier: MIT OR Apache-2.0
//! Sealed [`PairingRecord`] persistence — a pairing that survives an app restart.
//!
//! A [`PairingRecord`] holds the peer's pinned identity key, the channel binding,
//! and the **forward-secret `session_root`** (ephemeral-derived; NEVER the wallet
//! seed). To make a pairing survive a restart WITHOUT re-running the human SAS,
//! the record must be persisted — but the `session_root` is a secret, so it is
//! **never written in plaintext**. This module serialises the record and hands it
//! to the canonical [`crate::seal`] (key-committing, context-bound XChaCha20-
//! Poly1305), so what touches disk is a sealed blob and nothing else.
//!
//! ```text
//! record  --serialise-->  plaintext (Zeroizing)  --seal(storage_key, RECORD_CONTEXT)-->  blob on disk
//! blob    --open(storage_key, RECORD_CONTEXT)-->  plaintext (Zeroizing)  --parse-->  record
//! ```
//!
//! - **The `session_root` is sealed at rest, always.** The plaintext form exists
//!   only transiently in a [`Zeroizing`] buffer that is wiped on drop; the caller
//!   never sees it and it is never on disk in the clear.
//! - **Fail-closed load.** A wrong `storage_key`, a wrong context, or any tamper
//!   makes [`load`] return an error and NO record (the seal's key-commitment +
//!   AEAD tag both have to verify). A corrupted or truncated blob is refused.
//! - **Revoked records are never persisted.** [`save`] refuses a revoked record;
//!   an unpair/revoke must delete the on-disk blob, not rewrite it. Consequently a
//!   loaded record is always non-revoked.
//! - **The storage key is the caller's job.** On desktop it is a `postern-vault`
//!   key (Argon2id passphrase or OS keystore); on mobile it is a StrongBox/Secure-
//!   Enclave-wrapped key. This module consumes 32 bytes and derives everything
//!   else per-seal; it does not manage the key's own at-rest protection.
//!
//! ## What is intentionally NOT persisted: channel counters
//! The live [`crate::channel::Channel`] send-counter / receive-watermark are
//! **not** saved. Reconnect does a clean, fresh, forward-secret re-handshake
//! ([`crate::resume`]) that mints a NEW session key and session id with counters
//! reset — so there is no fragile "counter continuity" to persist and no risk of a
//! rolled-back counter re-opening the replay window. Only the long-lived pairing
//! anchor (pins + `session_root`) is persisted. See [`crate::resume`] for why the
//! re-handshake is the safe choice.

use zeroize::Zeroizing;

use crate::binding::BINDING_LEN;
use crate::hybrid::SESSION_KEY_LEN;
use crate::record::{PairingRecord, Role};
use crate::seal::{self, SealError};

/// The seal context that binds a persisted record. A blob sealed under this
/// context can only be opened for this purpose (domain separation from any other
/// use of the same storage key).
pub const RECORD_CONTEXT: &[u8] = b"postern-pairing/record/v1";

/// Magic + format tag inside the sealed plaintext (defends against feeding an
/// unrelated blob that happens to open under the same key/context).
const RECORD_MAGIC: &[u8] = b"PPRC";
const RECORD_FORMAT: u8 = 1;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PersistError {
    /// Unseal failed: wrong storage key, wrong context, or tampered/rolled-back
    /// blob. Fail-closed — no record is produced.
    #[error("sealed record could not be opened — wrong key or tampered (fail closed)")]
    Seal,
    /// The blob opened, but its contents are not a valid record (wrong magic,
    /// bad length, or a bad field).
    #[error("record is malformed after unseal")]
    Malformed,
    /// The plaintext used an unsupported record format version.
    #[error("unsupported persisted record format")]
    Version,
    /// Refusing to persist a revoked record — delete the blob instead.
    #[error("refusing to persist a revoked record; delete the stored blob instead")]
    Revoked,
}

impl From<SealError> for PersistError {
    fn from(_: SealError) -> Self {
        // Both seal and open failures collapse to the fail-closed variant; the
        // caller must not be able to distinguish "wrong key" from "tampered".
        PersistError::Seal
    }
}

fn role_to_byte(role: Role) -> u8 {
    match role {
        Role::Custodian => 0,
        Role::Terminal => 1,
    }
}

fn role_from_byte(b: u8) -> Option<Role> {
    match b {
        0 => Some(Role::Custodian),
        1 => Some(Role::Terminal),
        _ => None,
    }
}

fn put_lv(out: &mut Vec<u8>, v: &[u8]) {
    let len = v.len().min(u32::MAX as usize) as u32;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&v[..len as usize]);
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Some(s)
    }
    fn take_lv(&mut self) -> Option<&'a [u8]> {
        let len_bytes = self.take(4)?;
        let len = u32::from_be_bytes(len_bytes.try_into().ok()?) as usize;
        self.take(len)
    }
    fn done(&self) -> bool {
        self.pos == self.buf.len()
    }
}

/// Serialise a record's fields into a plaintext buffer (wiped on drop). Layout:
/// `MAGIC ‖ format ‖ role ‖ lv(nickname) ‖ lv(peer_identity_pub) ‖
///  channel_binding(32) ‖ session_root(32)`.
fn to_plaintext(record: &PairingRecord) -> Zeroizing<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(RECORD_MAGIC);
    out.push(RECORD_FORMAT);
    out.push(role_to_byte(record.role));
    put_lv(&mut out, record.nickname.as_bytes());
    put_lv(&mut out, &record.peer_identity_pub);
    out.extend_from_slice(&record.channel_binding);
    out.extend_from_slice(&*record.session_root);
    Zeroizing::new(out)
}

fn from_plaintext(pt: &[u8]) -> Result<PairingRecord, PersistError> {
    let mut c = Cursor::new(pt);
    let magic = c.take(RECORD_MAGIC.len()).ok_or(PersistError::Malformed)?;
    if magic != RECORD_MAGIC {
        return Err(PersistError::Malformed);
    }
    let format = *c.take(1).ok_or(PersistError::Malformed)?.first().unwrap();
    if format != RECORD_FORMAT {
        return Err(PersistError::Version);
    }
    let role_b = *c.take(1).ok_or(PersistError::Malformed)?.first().unwrap();
    let role = role_from_byte(role_b).ok_or(PersistError::Malformed)?;
    let nickname = String::from_utf8(c.take_lv().ok_or(PersistError::Malformed)?.to_vec())
        .map_err(|_| PersistError::Malformed)?;
    let peer_identity_pub = c.take_lv().ok_or(PersistError::Malformed)?.to_vec();

    let binding_slice = c.take(BINDING_LEN).ok_or(PersistError::Malformed)?;
    let mut channel_binding = [0u8; BINDING_LEN];
    channel_binding.copy_from_slice(binding_slice);

    let root_slice = c.take(SESSION_KEY_LEN).ok_or(PersistError::Malformed)?;
    let mut session_root = Zeroizing::new([0u8; SESSION_KEY_LEN]);
    session_root.copy_from_slice(root_slice);

    // No trailing garbage — a well-formed record consumes the whole plaintext.
    if !c.done() {
        return Err(PersistError::Malformed);
    }

    Ok(PairingRecord::new(
        role,
        nickname,
        peer_identity_pub,
        channel_binding,
        session_root,
    ))
}

/// Seal a record for storage. The returned bytes are the ONLY thing that should
/// touch disk. Refuses a revoked record (delete the blob instead).
///
/// `storage_key` is the caller's device-storage key (vault/StrongBox-protected).
pub fn save(record: &PairingRecord, storage_key: &[u8; 32]) -> Result<Vec<u8>, PersistError> {
    if record.is_revoked() {
        return Err(PersistError::Revoked);
    }
    let plaintext = to_plaintext(record);
    Ok(seal::seal(storage_key, RECORD_CONTEXT, &plaintext)?)
}

/// Open a sealed record. Fail-closed: a wrong key / wrong context / tamper yields
/// [`PersistError::Seal`] and NO record. A loaded record is always non-revoked
/// (revoked ones are never persisted by [`save`]).
pub fn load(sealed: &[u8], storage_key: &[u8; 32]) -> Result<PairingRecord, PersistError> {
    let pt = seal::open(storage_key, RECORD_CONTEXT, sealed)?;
    from_plaintext(&pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> PairingRecord {
        PairingRecord::new(
            Role::Terminal,
            "Tiago's ThinkPad",
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            [0x9au8; BINDING_LEN],
            Zeroizing::new([0x5cu8; SESSION_KEY_LEN]),
        )
    }

    #[test]
    fn save_load_roundtrip_survives_restart() {
        let key = [0x21u8; 32];
        let blob = save(&record(), &key).unwrap();
        let loaded = load(&blob, &key).unwrap();
        assert_eq!(loaded.role, Role::Terminal);
        assert_eq!(loaded.nickname, "Tiago's ThinkPad");
        assert!(loaded.peer_matches(&[0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(&*loaded.session_root, &[0x5cu8; SESSION_KEY_LEN]);
        assert!(!loaded.is_revoked());
    }

    #[test]
    fn session_root_is_never_in_the_clear() {
        let key = [0x21u8; 32];
        let blob = save(&record(), &key).unwrap();
        // The session root (0x5c×32) must NOT appear anywhere in the sealed blob.
        let root = [0x5cu8; SESSION_KEY_LEN];
        assert!(
            !blob.windows(SESSION_KEY_LEN).any(|w| w == root),
            "session_root must be sealed, never plaintext at rest"
        );
    }

    #[test]
    fn wrong_key_fails_closed_no_record() {
        let blob = save(&record(), &[1u8; 32]).unwrap();
        assert_eq!(load(&blob, &[2u8; 32]).unwrap_err(), PersistError::Seal);
    }

    #[test]
    fn tampered_blob_fails_closed() {
        let key = [7u8; 32];
        let mut blob = save(&record(), &key).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        assert_eq!(load(&blob, &key).unwrap_err(), PersistError::Seal);
    }

    #[test]
    fn revoked_record_is_not_persisted() {
        let mut r = record();
        r.revoke();
        assert_eq!(save(&r, &[3u8; 32]).unwrap_err(), PersistError::Revoked);
    }

    #[test]
    fn custodian_role_roundtrips() {
        let key = [8u8; 32];
        let r = PairingRecord::new(
            Role::Custodian,
            "phone",
            vec![1, 2, 3],
            [0u8; BINDING_LEN],
            Zeroizing::new([0x11u8; SESSION_KEY_LEN]),
        );
        let loaded = load(&save(&r, &key).unwrap(), &key).unwrap();
        assert_eq!(loaded.role, Role::Custodian);
    }
}
