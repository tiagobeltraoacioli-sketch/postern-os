//! D-Bus client interfaces to **ModemManager** (`org.freedesktop.ModemManager1`).
//!
//! ModemManager is the GPL system daemon that owns the modem on Linux phones
//! (postmarketOS/Mobian stack; oFono is the alternative — same posture, and a
//! future `ofono` module can mirror these proxies if a device needs it).
//! We consume its **stable D-Bus API** over the system bus — IPC across a
//! process boundary, NOT a fork/embed of GPL code, so it passes the repo
//! license rule. zbus itself is MIT, pure Rust, no libdbus link.
//!
//! Signatures follow the ModemManager 1.x introspection documents
//! (`org.freedesktop.ModemManager1.Modem.Messaging`, `.Sms`, `.Modem.Voice`,
//! `.Call`). **Validate against the live daemon on first device bring-up** —
//! a host without a modem has nothing at these paths.

use std::collections::HashMap;
use zbus::proxy;
use zbus::zvariant::{OwnedObjectPath, Value};

/// Well-known bus name of the daemon (system bus).
pub const MM_SERVICE: &str = "org.freedesktop.ModemManager1";
/// Root object path (an `ObjectManager` exporting one object per modem).
pub const MM_PATH: &str = "/org/freedesktop/ModemManager1";

/// `org.freedesktop.DBus.ObjectManager` on the MM root — how we discover
/// modems (each managed object with a `.Modem` interface is one modem).
#[proxy(
    interface = "org.freedesktop.DBus.ObjectManager",
    default_service = "org.freedesktop.ModemManager1",
    default_path = "/org/freedesktop/ModemManager1"
)]
pub trait MmObjectManager {
    /// objects → { interface → { property → value } }
    fn get_managed_objects(
        &self,
    ) -> zbus::Result<
        HashMap<OwnedObjectPath, HashMap<String, HashMap<String, zbus::zvariant::OwnedValue>>>,
    >;
}

/// `org.freedesktop.ModemManager1.Modem.Messaging` — the SMS surface of a modem.
#[proxy(
    interface = "org.freedesktop.ModemManager1.Modem.Messaging",
    default_service = "org.freedesktop.ModemManager1"
)]
pub trait Messaging {
    /// Create an SMS object from properties (`number`: s, `text`: s, …).
    /// Returns the new `.Sms` object path; it is not sent until `Sms::send`.
    fn create(&self, properties: HashMap<&str, &Value<'_>>) -> zbus::Result<OwnedObjectPath>;

    /// All message object paths known to the modem (sent, received, drafts).
    fn list(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// Delete a message from the modem/SIM storage.
    fn delete(&self, path: &zbus::zvariant::ObjectPath<'_>) -> zbus::Result<()>;

    /// Emitted for every new message; `received == true` means an incoming
    /// SMS arrived from the network — the app's receive path.
    #[zbus(signal)]
    fn added(&self, path: OwnedObjectPath, received: bool) -> zbus::Result<()>;

    #[zbus(property)]
    fn messages(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
}

/// `org.freedesktop.ModemManager1.Sms` — one SMS object.
#[proxy(
    interface = "org.freedesktop.ModemManager1.Sms",
    default_service = "org.freedesktop.ModemManager1"
)]
pub trait Sms {
    /// Hand the message to the network via the modem. Requires registration
    /// on a carrier — this is the moment the SMS leaves the device in
    /// PLAINTEXT toward the operator (see the crate honesty note).
    fn send(&self) -> zbus::Result<()>;

    /// Store the message on the given storage (`MMSmsStorage`).
    fn store(&self, storage: u32) -> zbus::Result<()>;

    #[zbus(property)]
    fn number(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn text(&self) -> zbus::Result<String>;
    /// `MMSmsState` — map with [`crate::types::SmsState::from_mm`].
    #[zbus(property)]
    fn state(&self) -> zbus::Result<u32>;
    /// `MMSmsPduType` — 1 = deliver (incoming), 2 = submit (outgoing).
    #[zbus(property)]
    fn pdu_type(&self) -> zbus::Result<u32>;
    /// ISO 8601 carrier timestamp (incoming messages).
    #[zbus(property)]
    fn timestamp(&self) -> zbus::Result<String>;
}

/// `org.freedesktop.ModemManager1.Modem.Voice` — the call surface of a modem.
#[proxy(
    interface = "org.freedesktop.ModemManager1.Modem.Voice",
    default_service = "org.freedesktop.ModemManager1"
)]
pub trait Voice {
    /// Create a call object (`number`: s). Not dialed until `Call::start`.
    fn create_call(&self, properties: HashMap<&str, &Value<'_>>) -> zbus::Result<OwnedObjectPath>;

    fn list_calls(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
    fn delete_call(&self, path: &zbus::zvariant::ObjectPath<'_>) -> zbus::Result<()>;

    /// Hang up all active calls.
    fn hangup_all(&self) -> zbus::Result<()>;
    /// Hold the active call and accept the waiting one.
    fn hold_and_accept(&self) -> zbus::Result<()>;
    /// Hang up the active call and accept the waiting one.
    fn hangup_and_accept(&self) -> zbus::Result<()>;

    /// Emitted when a call appears — for incoming calls this is the ring.
    #[zbus(signal)]
    fn call_added(&self, path: OwnedObjectPath) -> zbus::Result<()>;

    #[zbus(property)]
    fn calls(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
    /// True when only emergency numbers are allowed (no SIM / no service).
    #[zbus(property)]
    fn emergency_only(&self) -> zbus::Result<bool>;
}

/// `org.freedesktop.ModemManager1.Call` — one voice call.
#[proxy(
    interface = "org.freedesktop.ModemManager1.Call",
    default_service = "org.freedesktop.ModemManager1"
)]
pub trait Call {
    /// Dial (outgoing call previously created via `Voice::create_call`).
    fn start(&self) -> zbus::Result<()>;
    /// Accept an incoming call.
    fn accept(&self) -> zbus::Result<()>;
    /// Hang up / reject.
    fn hangup(&self) -> zbus::Result<()>;
    /// Send DTMF tones ("0"–"9", "*", "#") during an active call.
    fn send_dtmf(&self, dtmf: &str) -> zbus::Result<()>;

    /// (old, new, `MMCallStateReason`) — drives the in-call UI + the log.
    /// Rust-side name differs from the D-Bus `StateChanged` so the generated
    /// stream doesn't collide with the `state` PROPERTY's change stream.
    #[zbus(signal, name = "StateChanged")]
    fn call_state_changed(&self, old: i32, new: i32, reason: u32) -> zbus::Result<()>;

    /// `MMCallState` — map with [`crate::types::CallState::from_mm`].
    #[zbus(property)]
    fn state(&self) -> zbus::Result<i32>;
    /// `MMCallDirection`: 1 = incoming, 2 = outgoing.
    #[zbus(property)]
    fn direction(&self) -> zbus::Result<i32>;
    #[zbus(property)]
    fn number(&self) -> zbus::Result<String>;
}
