//! Postern Telephony — carrier SMS + cellular voice for Postern OS Mobile
//! (a Postern Labs product).
//!
//! Two apps share this core:
//! - **Postern SMS** ([`sms::SmsService`]) — send/receive SMS **via the mobile
//!   operator** (the modem/SIM), with MMS through `mmsd-tng` (phase 2).
//! - **Postern Dialer** ([`voice::VoiceService`]) — cellular/PSTN voice calls:
//!   dial, accept, hang up, DTMF, and an encrypted call log.
//!
//! # How it talks to the network (the honest architecture)
//!
//! On a Linux phone the modem is owned by the **ModemManager** system daemon
//! (the same stack postmarketOS/Mobian use; oFono is the alternative). This
//! crate is a **fresh MIT/Apache D-Bus client** to those daemons:
//!
//! ```text
//!  Postern SMS / Postern Dialer  (touch UI — future, like the wallet UI)
//!            │
//!  postern-telephony (this crate, MIT OR Apache-2.0)
//!    ├── sms::SmsService      ──D-Bus──▶ ModemManager .Modem.Messaging/.Sms (GPL daemon)
//!    ├── mms  (phase 2)       ──D-Bus──▶ mmsd-tng  org.ofono.mms            (GPL daemon)
//!    ├── voice::VoiceService  ──D-Bus──▶ ModemManager .Modem.Voice/.Call    (GPL daemon)
//!    ├── audio (call routing) ──D-Bus──▶ callaudiod org.mobian_project      (GPL daemon)
//!    └── store::SealedTelephonyStore — postern-core AEAD, key from the vault
//!                                            │
//!                                     modem firmware / SIM / carrier
//! ```
//!
//! **License posture:** ModemManager/oFono/mmsd-tng/callaudiod are GPL, but
//! they are *system services reached over D-Bus IPC* — a process boundary,
//! like syscalls into the GPL kernel. That is neither forking nor embedding
//! GPL code and is allowed under the repo rule. What we do NOT do: fork or
//! embed GPL clients (GNOME Calls, Chatty) — this crate is written fresh,
//! per the roadmap's own rule for the messenger ("build a fresh Apache/MIT
//! client — never fork").
//!
//! # Honesty
//!
//! - **Carrier SMS/voice is NOT private on the wire.** SMS is plaintext to
//!   the carrier; calls are lawful-intercept-accessible; SS7 is attackable;
//!   the tower always knows your location and IMEI/IMSI. This crate's value
//!   is a *hardened local client*: encrypted-at-rest store, no cloud, no
//!   telemetry, minimal local metadata. For anything sensitive, Postern
//!   steers users to the E2EE Matrix messenger (`postern-messenger`).
//! - **A real modem/SIM/device is required to run.** The D-Bus layer compiles
//!   everywhere but only connects on a Linux phone with ModemManager on the
//!   system bus. Everything pure (models, encrypted store) is unit-tested on
//!   any host.
//! - D-Bus signatures were written against the ModemManager 1.x introspection
//!   docs; validate against the live daemon on first device bring-up.

pub mod number;
pub mod store;
pub mod types;

#[cfg(feature = "dbus")]
pub mod audio;
#[cfg(feature = "dbus")]
pub mod mm;
#[cfg(feature = "dbus")]
pub mod mms;
/// Live-device modem probe (roadmap B4 telephony device-path smoke check).
#[cfg(feature = "dbus")]
pub mod probe;
#[cfg(feature = "dbus")]
pub mod sms;
#[cfg(feature = "dbus")]
pub mod voice;

/// Errors across the telephony core.
#[derive(Debug, thiserror::Error)]
pub enum TelephonyError {
    /// D-Bus transport / daemon error (no bus, daemon missing, call failed).
    #[cfg(feature = "dbus")]
    #[error("D-Bus error: {0}")]
    Dbus(#[from] zbus::Error),
    /// No modem is present/enabled (no device, no SIM, or ModemManager
    /// hasn't exported one). Expected on any non-phone host.
    #[error("no modem available — requires a Linux phone with ModemManager and a SIM")]
    NoModem,
    /// The modem exists but the operation isn't possible right now
    /// (e.g. no registration, emergency-only, call state mismatch).
    #[error("modem not ready: {0}")]
    NotReady(String),
    /// The dial string is not a valid `+`-and-digits phone number (after
    /// stripping common separators). Rejected before it ever reaches the
    /// modem — see [`number::normalize_dial_string`].
    #[error("invalid phone number: expected an optional '+' followed by 2–15 digits")]
    InvalidNumber,
    /// Encrypted-store failure (wrong key, tamper, corrupt data).
    #[error("store error: {0}")]
    Store(#[from] store::StoreError),
    /// The feature is designed but not implemented yet (honest stub).
    #[error("not implemented yet: {0}")]
    Unimplemented(&'static str),
}
