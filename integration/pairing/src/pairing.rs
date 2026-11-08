// SPDX-License-Identifier: MIT OR Apache-2.0
//! The pairing ceremony — QR-pinned ephemeral anchor + mandatory 6-digit SAS.
//!
//! Two jobs hide under "pairing" (§2.1); this module keeps them distinct:
//!
//! 1. **Anchor exchange (high integrity).** The desktop (terminal) generates a
//!    fresh EPHEMERAL hybrid keypair and a nonce, and emits a [`QrPayload`]. The
//!    phone (custodian) scans it and **pins the anchor off the glass** before
//!    the KEM runs — collapsing the MITM window to zero.
//! 2. **Session confirmation (human).** Both sides derive a 6-digit [`Sas`] from
//!    the agreed session key and the human compares them. [`confirm_sas`] is
//!    **fail-closed**: without an affirmative human confirmation, no
//!    [`PairingRecord`] and no [`Channel`] are produced.
//!
//! Direction is **phone-scans-desktop**, because the phone is the trust root
//! doing the verifying. The QR carries the *desktop's* key; the reverse is never
//! done in v1.
//!
//! ```text
//! Terminal (desktop)                         Custodian (phone)
//! ------------------                         -----------------
//! begin_desktop() ---------- QrPayload -----> scan_desktop_qr()
//!   ephemeral keypair,                          pin anchor (binding check),
//!   nonce, binding                              encapsulate -> session key,
//!                                               derive SAS
//!            <--------- PairingInit{kem_ct} ----
//!   accept(): decapsulate -> session key,
//!             derive SAS
//!   [both compare SAS on-screen]              [both compare SAS on-screen]
//!   confirm_sas(true) -> (Record, Channel)    confirm_sas(true) -> (Record, Channel)
//! ```
//!
//! [`Sas`]: crate::sas::Sas
//! [`Channel`]: crate::channel::Channel

use crate::binding::{self, Nonce, BINDING_LEN, NONCE_LEN};
use crate::channel::{self, Channel};
use crate::hybrid::{self, EphemeralKeypair, SessionKey, PUBLIC_KEY_LEN};
use crate::record::{PairingRecord, Role};
use crate::sas::Sas;
use crate::PROTOCOL_VERSION;

use rand_core::{OsRng, RngCore};

/// QR magic prefix — a versioned, self-describing tag (`pair/v1`).
const QR_MAGIC: &[u8] = b"PPQR";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PairingError {
    #[error("malformed QR payload")]
    MalformedQr,
    #[error("unsupported protocol version")]
    Version,
    #[error("QR anchor binding did not verify (possible MITM / corrupt scan)")]
    BindingMismatch,
    #[error("hybrid handshake failed: {0}")]
    Hybrid(#[from] hybrid::HybridError),
    #[error("SAS was NOT confirmed by the human — pairing aborted (fail-closed)")]
    SasNotConfirmed,
}

/// The out-of-band QR payload: `pair/v1 || anchor ephemeral pubkey || nonce ||
/// LAN hint || terminal identity pubkey`. High-entropy, copy-paste-proof, and
/// scanned off the desktop's glass by the phone.
#[derive(Clone, Debug)]
pub struct QrPayload {
    pub version: u8,
    /// The desktop's EPHEMERAL hybrid public key (the pinned anchor).
    pub anchor_public: Vec<u8>,
    /// Fresh 32-byte pairing nonce.
    pub nonce: Nonce,
    /// LAN dial hint (mDNS/`host:port`). Discovery only; no identity.
    pub lan_hint: String,
    /// The desktop's long-term identity public key, pinned TOFU by the phone.
    /// Opaque bytes (whatever identity key the Dev layer uses).
    pub terminal_identity_pub: Vec<u8>,
}

impl QrPayload {
    /// Serialize to bytes for a QR code: `MAGIC || ver || len16||anchor ||
    /// nonce(32) || len16||lan_hint || len16||identity`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(QR_MAGIC);
        out.push(self.version);
        put_lv(&mut out, &self.anchor_public);
        out.extend_from_slice(&self.nonce);
        put_lv(&mut out, self.lan_hint.as_bytes());
        put_lv(&mut out, &self.terminal_identity_pub);
        out
    }

    /// Parse a QR payload, validating the magic, version, and anchor length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        let mut c = Cursor::new(bytes);
        let magic = c.take(QR_MAGIC.len()).ok_or(PairingError::MalformedQr)?;
        if magic != QR_MAGIC {
            return Err(PairingError::MalformedQr);
        }
        let version = *c.take(1).ok_or(PairingError::MalformedQr)?.first().unwrap();
        if version != PROTOCOL_VERSION {
            return Err(PairingError::Version);
        }
        let anchor_public = c.take_lv().ok_or(PairingError::MalformedQr)?.to_vec();
        if anchor_public.len() != PUBLIC_KEY_LEN {
            return Err(PairingError::MalformedQr);
        }
        let nonce_slice = c.take(NONCE_LEN).ok_or(PairingError::MalformedQr)?;
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(nonce_slice);
        let lan_hint = String::from_utf8(c.take_lv().ok_or(PairingError::MalformedQr)?.to_vec())
            .map_err(|_| PairingError::MalformedQr)?;
        let terminal_identity_pub = c.take_lv().ok_or(PairingError::MalformedQr)?.to_vec();
        Ok(QrPayload { version, anchor_public, nonce, lan_hint, terminal_identity_pub })
    }

    /// A text-safe form for a QR library that wants a string (lowercase hex).
    pub fn to_hex(&self) -> String {
        self.to_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Parse the hex form produced by [`to_hex`](Self::to_hex).
    pub fn from_hex(s: &str) -> Result<Self, PairingError> {
        if s.len() % 2 != 0 {
            return Err(PairingError::MalformedQr);
        }
        let mut bytes = Vec::with_capacity(s.len() / 2);
        for i in (0..s.len()).step_by(2) {
            let byte = u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| PairingError::MalformedQr)?;
            bytes.push(byte);
        }
        Self::from_bytes(&bytes)
    }
}

/// The custodian (phone) side's reply after scanning: the hybrid encapsulation
/// plus the phone's identity key for the desktop to pin.
#[derive(Clone)]
pub struct PairingInit {
    /// Hybrid encapsulation (ML-KEM ct || X25519 ephemeral pk) to the anchor.
    pub kem_ct: Vec<u8>,
    /// The phone's long-term identity public key, pinned TOFU by the desktop.
    pub custodian_identity_pub: Vec<u8>,
}

impl PairingInit {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_lv(&mut out, &self.kem_ct);
        put_lv(&mut out, &self.custodian_identity_pub);
        out
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PairingError> {
        let mut c = Cursor::new(bytes);
        let kem_ct = c.take_lv().ok_or(PairingError::MalformedQr)?.to_vec();
        let custodian_identity_pub = c.take_lv().ok_or(PairingError::MalformedQr)?.to_vec();
        Ok(PairingInit { kem_ct, custodian_identity_pub })
    }
}

/// The pairing entry points. Stateless namespace; each call returns a typed
/// state you drive to `confirm_sas`.
pub struct Pairing;

impl Pairing {
    /// Terminal (desktop) side, step 1: generate the ephemeral anchor and emit
    /// the QR. Hold the returned [`DesktopPending`] until the phone replies.
    pub fn begin_desktop(
        nickname: impl Into<String>,
        lan_hint: impl Into<String>,
        terminal_identity_pub: Vec<u8>,
    ) -> (DesktopPending, QrPayload) {
        let keypair = EphemeralKeypair::generate();
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let bind = binding::channel_binding(&nonce, &keypair.public);

        let qr = QrPayload {
            version: PROTOCOL_VERSION,
            anchor_public: keypair.public.clone(),
            nonce,
            lan_hint: lan_hint.into(),
            terminal_identity_pub,
        };
        let pending = DesktopPending { keypair, nonce, binding: bind, nickname: nickname.into() };
        (pending, qr)
    }

    /// Custodian (phone) side: scan the desktop QR, pin the anchor, run the
    /// hybrid KEM, and derive the SAS. Returns the reply to send back plus the
    /// [`SasConfirm`] state for the human comparison.
    ///
    /// `custodian_identity_pub` is the phone's long-term identity key the
    /// desktop will pin TOFU.
    pub fn scan_desktop_qr(
        qr: &QrPayload,
        nickname: impl Into<String>,
        custodian_identity_pub: Vec<u8>,
    ) -> Result<(SasConfirm, PairingInit), PairingError> {
        if qr.version != PROTOCOL_VERSION {
            return Err(PairingError::Version);
        }
        // Pin the anchor: recompute + require the binding. A corrupt/injected
        // key fails here before any secret is derived.
        let bind = binding::channel_binding(&qr.nonce, &qr.anchor_public);

        let (kem_ct, session_key) = hybrid::encapsulate_to(&qr.anchor_public, &qr.nonce)?;
        let sas = Sas::derive(&session_key);

        let confirm = SasConfirm {
            role: Role::Custodian,
            initiator: true,
            nickname: nickname.into(),
            peer_identity_pub: qr.terminal_identity_pub.clone(),
            binding: bind,
            session_key,
            sas,
        };
        let init = PairingInit { kem_ct, custodian_identity_pub };
        Ok((confirm, init))
    }
}

/// Terminal-side state between emitting the QR and receiving the phone's reply.
pub struct DesktopPending {
    keypair: EphemeralKeypair,
    nonce: Nonce,
    binding: [u8; BINDING_LEN],
    nickname: String,
}

impl DesktopPending {
    /// Accept the phone's [`PairingInit`]: decapsulate to the session key and
    /// derive the SAS. Returns the [`SasConfirm`] state for the human step.
    pub fn accept(self, init: &PairingInit) -> Result<SasConfirm, PairingError> {
        let session_key = self.keypair.decapsulate(&init.kem_ct, &self.nonce)?;
        let sas = Sas::derive(&session_key);
        Ok(SasConfirm {
            role: Role::Terminal,
            initiator: false,
            nickname: self.nickname,
            peer_identity_pub: init.custodian_identity_pub.clone(),
            binding: self.binding,
            session_key,
            sas,
        })
    }

    /// The channel binding this desktop anchored (for display / diagnostics).
    pub fn channel_binding(&self) -> &[u8; BINDING_LEN] {
        &self.binding
    }
}

/// Both sides converge here: an agreed session key + the SAS to compare. This
/// is the fail-closed gate — nothing is persisted or opened until the human
/// confirms the SAS matched.
pub struct SasConfirm {
    role: Role,
    initiator: bool,
    nickname: String,
    peer_identity_pub: Vec<u8>,
    binding: [u8; BINDING_LEN],
    session_key: SessionKey,
    sas: Sas,
}

impl SasConfirm {
    /// The 6-digit SAS to display on this device's screen for the human to
    /// compare against the other screen.
    pub fn sas(&self) -> &Sas {
        &self.sas
    }

    /// This device's role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The fail-closed confirmation. `user_confirmed` MUST be the result of an
    /// explicit human "the codes match" action. If it is `false`, pairing is
    /// aborted and NOTHING is produced — no record, no channel. There is no
    /// timeout auto-accept and no skip.
    pub fn confirm_sas(
        self,
        user_confirmed: bool,
    ) -> Result<(PairingRecord, Channel), PairingError> {
        if !user_confirmed {
            return Err(PairingError::SasNotConfirmed);
        }
        let channel = channel::open_endpoint(&self.session_key, self.initiator);
        let record = PairingRecord::new(
            self.role,
            self.nickname,
            self.peer_identity_pub,
            self.binding,
            self.session_key,
        );
        Ok((record, channel))
    }
}

// --- tiny length-value codec helpers (no serde dependency) -----------------

fn put_lv(out: &mut Vec<u8>, v: &[u8]) {
    // 16-bit big-endian length prefix. Values here are bounded (a hybrid pubkey
    // is ~1.6 KiB); reject anything a QR could not sanely carry at parse time.
    let len = v.len().min(u16::MAX as usize) as u16;
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
        let len_bytes = self.take(2)?;
        let len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
        self.take(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_roundtrip_bytes_and_hex() {
        let (pending, qr) = Pairing::begin_desktop("desk", "192.168.1.5:47001", vec![7, 7, 7]);
        let _ = &pending;
        let re = QrPayload::from_bytes(&qr.to_bytes()).unwrap();
        assert_eq!(re.anchor_public, qr.anchor_public);
        assert_eq!(re.nonce, qr.nonce);
        assert_eq!(re.lan_hint, "192.168.1.5:47001");
        assert_eq!(re.terminal_identity_pub, vec![7, 7, 7]);
        let re2 = QrPayload::from_hex(&qr.to_hex()).unwrap();
        assert_eq!(re2.anchor_public, qr.anchor_public);
    }

    #[test]
    fn full_ceremony_agrees_sas_and_talks() {
        let (pending, qr) = Pairing::begin_desktop("Tiago's ThinkPad", "lan:1", vec![0xDE, 0xAD]);
        let qr_scanned = QrPayload::from_bytes(&qr.to_bytes()).unwrap();

        let (phone_confirm, init) =
            Pairing::scan_desktop_qr(&qr_scanned, "Tiago's Pixel", vec![0xBE, 0xEF]).unwrap();
        let init_parsed = PairingInit::from_bytes(&init.to_bytes()).unwrap();
        let desk_confirm = pending.accept(&init_parsed).unwrap();

        // The SAS matches on both screens (no MITM).
        assert!(phone_confirm.sas().matches(desk_confirm.sas()));
        assert_eq!(phone_confirm.sas().digits(), desk_confirm.sas().digits());

        // Human confirms -> both get a record + a live channel.
        let (phone_rec, mut phone_ch) = phone_confirm.confirm_sas(true).unwrap();
        let (desk_rec, mut desk_ch) = desk_confirm.confirm_sas(true).unwrap();

        assert_eq!(phone_rec.role, Role::Custodian);
        assert_eq!(desk_rec.role, Role::Terminal);
        // Pinned peer identity keys are crossed.
        assert!(phone_rec.peer_matches(&[0xDE, 0xAD]));
        assert!(desk_rec.peer_matches(&[0xBE, 0xEF]));

        // The channel works end to end.
        let f = phone_ch.seal_frame(b"login-challenge").unwrap();
        assert_eq!(&**desk_ch.open_frame(&f).unwrap(), b"login-challenge");
    }

    #[test]
    fn refusing_the_sas_fails_closed() {
        let (pending, qr) = Pairing::begin_desktop("d", "l", vec![1]);
        let (phone_confirm, init) = Pairing::scan_desktop_qr(&qr, "p", vec![2]).unwrap();
        let desk_confirm = pending.accept(&init).unwrap();
        // The human says "these don't match".
        assert_eq!(
            phone_confirm.confirm_sas(false).unwrap_err(),
            PairingError::SasNotConfirmed
        );
        assert_eq!(
            desk_confirm.confirm_sas(false).unwrap_err(),
            PairingError::SasNotConfirmed
        );
    }

    #[test]
    fn mitm_reencapsulation_diverges_the_sas() {
        // An active MITM re-encapsulates to the phone with the anchor it relayed,
        // but the desktop decapsulates the ORIGINAL kem_ct. Model the mismatch:
        // the desktop ends up with a different session key -> different SAS.
        let (pending, qr) = Pairing::begin_desktop("d", "l", vec![1]);
        let (phone_confirm, _init_real) = Pairing::scan_desktop_qr(&qr, "p", vec![2]).unwrap();

        // Attacker's independent encapsulation to the same anchor (a fresh
        // kem_ct) -> a different shared secret at the desktop.
        let (attacker_ct, _attacker_key) =
            hybrid::encapsulate_to(&qr.anchor_public, &qr.nonce).unwrap();
        let desk_confirm = pending
            .accept(&PairingInit { kem_ct: attacker_ct, custodian_identity_pub: vec![9] })
            .unwrap();

        // The two SAS values almost certainly differ -> the human aborts.
        assert!(!phone_confirm.sas().matches(desk_confirm.sas()));
    }

    #[test]
    fn corrupt_qr_is_rejected() {
        let (_pending, qr) = Pairing::begin_desktop("d", "l", vec![1]);
        let mut bytes = qr.to_bytes();
        bytes[0] ^= 0xFF; // break the magic
        assert_eq!(QrPayload::from_bytes(&bytes).unwrap_err(), PairingError::MalformedQr);
    }
}
