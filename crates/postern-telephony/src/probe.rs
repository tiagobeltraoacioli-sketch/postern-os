// SPDX-License-Identifier: MIT OR Apache-2.0
//! Live-device probe for the Postern OS Mobile telephony path (roadmap B4).
//!
//! Enumerates the modems ModemManager exports on the system bus and reports,
//! per modem, the vendor/model/IMEI, the modem state, and whether the voice
//! and messaging (SMS) D-Bus surfaces are present. This is the honest smoke
//! check that the telephony *device path* is live — it CONNECTS only on a real
//! Linux phone with a modem + SIM. Under `qemu-system-aarch64 -M virt` there is
//! no modem, so [`discover`] returns an empty list: QEMU ≠ hardware.
//!
//! It touches only discovery (read-only `GetManagedObjects` + property reads) —
//! it never sends an SMS or places a call, so running it is side-effect-free.

use crate::mm::MmObjectManagerProxy;
use crate::TelephonyError;
use std::collections::HashMap;
use zbus::zvariant::OwnedValue;
use zbus::Connection;

/// A managed object is a modem iff it exports this interface.
const MODEM_IFACE: &str = "org.freedesktop.ModemManager1.Modem";
const VOICE_IFACE: &str = "org.freedesktop.ModemManager1.Modem.Voice";
const MESSAGING_IFACE: &str = "org.freedesktop.ModemManager1.Modem.Messaging";

/// What the probe learned about one modem the daemon exports.
#[derive(Debug, Clone)]
pub struct ModemInfo {
    /// The modem's D-Bus object path (e.g. `/org/freedesktop/ModemManager1/Modem/0`).
    pub path: String,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    /// `EquipmentIdentifier` — the IMEI (device-identifying; carrier always sees it).
    pub equipment_id: Option<String>,
    /// `MMModemState` (signed) — map with [`state_name`].
    pub state: Option<i32>,
    /// The `Modem.Voice` (dialer) surface is present on this modem.
    pub has_voice: bool,
    /// The `Modem.Messaging` (SMS) surface is present on this modem.
    pub has_messaging: bool,
}

impl ModemInfo {
    /// Human-readable modem state.
    pub fn state_name(&self) -> &'static str {
        state_name(self.state)
    }
}

/// Map a `MMModemState` value to a label (values per the ModemManager 1.x docs).
pub fn state_name(state: Option<i32>) -> &'static str {
    match state {
        Some(-1) => "failed",
        Some(0) => "unknown",
        Some(1) => "initializing",
        Some(2) => "locked (PIN/PUK)",
        Some(3) => "disabled",
        Some(4) => "disabling",
        Some(5) => "enabling",
        Some(6) => "enabled",
        Some(7) => "searching",
        Some(8) => "registered",
        Some(9) => "disconnecting",
        Some(10) => "connecting",
        Some(11) => "connected",
        _ => "n/a",
    }
}

/// Connect to the system bus and enumerate modems. Errors off-device
/// (`TelephonyError::Dbus` with no bus / daemon); returns `Ok(vec![])` when the
/// daemon runs but exports no modem (the QEMU / no-SIM case).
pub async fn discover() -> Result<Vec<ModemInfo>, TelephonyError> {
    let conn = Connection::system().await?;
    discover_on(&conn).await
}

/// Enumerate modems on an existing connection (testable seam).
pub async fn discover_on(conn: &Connection) -> Result<Vec<ModemInfo>, TelephonyError> {
    let om = MmObjectManagerProxy::new(conn).await?;
    let objects = om.get_managed_objects().await?;
    let mut out = Vec::new();
    for (path, ifaces) in objects {
        let Some(props) = ifaces.get(MODEM_IFACE) else {
            continue;
        };
        out.push(ModemInfo {
            path: path.to_string(),
            manufacturer: prop_string(props, "Manufacturer"),
            model: prop_string(props, "Model"),
            equipment_id: prop_string(props, "EquipmentIdentifier"),
            state: prop_i32(props, "State"),
            has_voice: ifaces.contains_key(VOICE_IFACE),
            has_messaging: ifaces.contains_key(MESSAGING_IFACE),
        });
    }
    Ok(out)
}

fn prop_string(props: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    props
        .get(key)
        .and_then(|v| String::try_from(v.clone()).ok())
        .filter(|s| !s.is_empty())
}

fn prop_i32(props: &HashMap<String, OwnedValue>, key: &str) -> Option<i32> {
    props.get(key).and_then(|v| i32::try_from(v.clone()).ok())
}

#[cfg(test)]
mod tests {
    use super::state_name;

    #[test]
    fn state_names_map() {
        assert_eq!(state_name(Some(8)), "registered");
        assert_eq!(state_name(Some(-1)), "failed");
        assert_eq!(state_name(Some(11)), "connected");
        assert_eq!(state_name(None), "n/a");
        assert_eq!(state_name(Some(99)), "n/a");
    }
}
