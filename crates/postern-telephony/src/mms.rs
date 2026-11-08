//! MMS via **mmsd-tng** (`org.ofono.mms`) — honest phase-2 scaffold.
//!
//! **Why MMS is not just "big SMS":** ModemManager does NOT implement MMS.
//! An MMS arrives as a WAP-push *notification* over SMS; the actual payload
//! is fetched over **HTTP from the carrier's MMSC** on a dedicated APN. On
//! Linux phones that user-agent role is played by the **mmsd-tng** daemon
//! (GPL — consumed strictly over its D-Bus API, same posture as ModemManager;
//! never embedded). It exposes the oFono-heritage `org.ofono.mms` interface
//! even when running on top of ModemManager.
//!
//! Status: proxy surface defined; the service wiring (APN config, attachment
//! handling, group MMS) needs a live device + carrier and is a stub.

use zbus::proxy;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

/// Well-known bus name of mmsd-tng (session bus in current packaging).
pub const MMS_SERVICE: &str = "org.ofono.mms";
pub const MMS_MANAGER_PATH: &str = "/org/ofono/mms";

/// `org.ofono.mms.Manager` — enumerates MMS "services" (one per SIM context).
#[proxy(
    interface = "org.ofono.mms.Manager",
    default_service = "org.ofono.mms",
    default_path = "/org/ofono/mms"
)]
pub trait MmsManager {
    /// (service object path, properties) pairs.
    fn get_services(
        &self,
    ) -> zbus::Result<Vec<(OwnedObjectPath, std::collections::HashMap<String, OwnedValue>)>>;
}

/// `org.ofono.mms.Service` — send/receive on one service.
#[proxy(interface = "org.ofono.mms.Service", default_service = "org.ofono.mms")]
pub trait MmsService {
    /// (message object path, properties) pairs — the inbox/outbox.
    fn get_messages(
        &self,
    ) -> zbus::Result<Vec<(OwnedObjectPath, std::collections::HashMap<String, OwnedValue>)>>;

    /// Send an MMS: recipients, SMIL body (may be empty), attachments as
    /// (content-id, content-type, local file path) triples.
    /// NOTE: validate the exact signature against the installed mmsd-tng —
    /// its API has grown variants (e.g. version/deletion flags) across
    /// releases; pin the daemon version in the OS image.
    fn send_message(
        &self,
        recipients: Vec<&str>,
        smil: &str,
        attachments: Vec<(&str, &str, &str)>,
    ) -> zbus::Result<OwnedObjectPath>;

    /// New incoming MMS (after mmsd-tng fetched it from the carrier MMSC).
    #[zbus(signal)]
    fn message_added(
        &self,
        path: OwnedObjectPath,
        properties: std::collections::HashMap<String, OwnedValue>,
    ) -> zbus::Result<()>;
}

/// Placeholder for the high-level MMS flow — requires a live device, a SIM
/// with an MMS APN, and a running mmsd-tng. Deliberately `Unimplemented`
/// rather than pretend-working.
pub async fn send_mms_stub() -> Result<(), crate::TelephonyError> {
    Err(crate::TelephonyError::Unimplemented(
        "MMS send: needs device + carrier MMSC via mmsd-tng (phase 2)",
    ))
}
