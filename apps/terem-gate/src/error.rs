// SPDX-License-Identifier: MIT OR Apache-2.0
//! Typed, fail-closed errors. Every variant is a **refusal to cross** --
//! silence and ambiguity are always a decline, never a silent crossing
//! (mirrors `apps/noporis-bridge-glue/src/{consent_record.rs,error.rs}`'s
//! discipline).

use thiserror::Error;

/// A `terem-gate` refusal. Covers both the signed-record 5-step check and the
/// mint-time guards (shared-folder disjointness, USB device identity).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TeremGateError {
    /// Step 1: the signature did not verify under the pinned host key. Either
    /// it was not minted by the host, or a pinned field was altered.
    #[error("consent signature invalid: not minted by the host, or a pinned field was altered")]
    BadSignature,
    /// Step 2: the record is bound to a different guest instance.
    #[error("consent bound to a different guest instance")]
    WrongInstance,
    /// Step 3: the record's pinned direction does not match the crossing's
    /// actual `from -> to`.
    #[error("consent direction mismatch: minted for a different from->to")]
    WrongDirection,
    /// Step 4: the record authorizes a different capability.
    #[error("consent capability mismatch: minted for a different bridge")]
    WrongCapability,
    /// Step 5: the time-box has lapsed (`now >= expires_at`) -- revocation
    /// path #4.
    #[error("consent expired: the time-box has lapsed")]
    Expired,
    /// Step 5: the record is not yet valid (`now < issued_at`).
    #[error("consent not yet valid: issued in the future")]
    NotYetValid,
    /// The record's pinned `hostPath` does not match the shared-folder
    /// crossing being attempted right now.
    #[error("shared-folder host path mismatch: does not match the pinned grant")]
    HostPathMismatch,
    /// The record's pinned USB device identity does not match the crossing
    /// being attempted right now.
    #[error("usb device mismatch: does not match the pinned grant")]
    UsbDeviceMismatch,
    /// Revocation path #1: this record was explicitly revoked by id.
    #[error("consent revoked: this authorization was explicitly withdrawn")]
    Revoked,
    /// Revocation path #2: this capability's lane was closed wholesale.
    #[error("consent bridge closed: this capability was revoked wholesale")]
    CapabilityClosed,
    /// Revocation path #3: the kill-switch is engaged.
    #[error("consent denied: kill-switch engaged, every bridge is cut")]
    KillSwitchEngaged,
    /// A `single`-scope record already spent its one crossing.
    #[error("consent already used: this single-use authorization is spent")]
    AlreadyUsed,
    /// No admitted record matches this crossing -- default-closed: nothing
    /// was ever minted for it.
    #[error("no consent: no live authorization exists for this bridge")]
    NoRecord,
    /// **Red-team fix (a).** `mint_shared_folder` refused: `host_path`
    /// overlaps a Terem-owned directory (state, audit, or `WINEPREFIX`), in
    /// either direction.
    #[error("shared folder host path {host_path:?} overlaps Terem's own {guarded} ({guarded_path:?}) -- refused")]
    SharedFolderPathOverlap {
        host_path: String,
        guarded: &'static str,
        guarded_path: String,
    },
    /// `mint` was called for [`crate::capability::Capability::SharedFolder`]
    /// without going through [`crate::consent_record::ConsentAuthority::
    /// mint_shared_folder`] -- the only path that runs the disjointness
    /// check. Fail-closed: there is no way to mint a `SharedFolder` grant
    /// that skips it.
    #[error("sharedFolder requires mint_shared_folder(), not the generic mint()")]
    MissingSharedFolderPath,
    /// `mint` was called for [`crate::capability::Capability::Usb`] without
    /// going through `mint_usb`.
    #[error("usb requires mint_usb(), not the generic mint()")]
    MissingUsbDevice,
    /// `mint_usb` was called with an empty serial -- an unidentified device
    /// cannot be allowlisted (still spoofable once identified, see
    /// [`crate::capability::USB_IDENTITY_SPOOFABLE_CAVEAT`], but an *empty*
    /// serial is not even a claimed identity).
    #[error("usb device has no serial: cannot allowlist an unidentified device")]
    UsbDeviceUnidentified,
}
