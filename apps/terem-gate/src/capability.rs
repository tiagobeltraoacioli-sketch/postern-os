// SPDX-License-Identifier: MIT OR Apache-2.0
//! The five Terem guest<->host bridges -- the only things that may cross the
//! sandbox boundary.
//!
//! Mirrors `apps/noporis-bridge-glue/src/capability.rs`'s `Capability` shape,
//! renamed to the desktop-sandbox set `docs/os-portal-v2/B-sandbox-consent.md`
//! SS2.3 specifies: `clipboard, files (sharedFolder), network, usb, audio`.
//! `widen.gpuPassthrough` is deliberately **excluded** -- SS2.4/SS3.0 of both
//! design docs classify GPU passthrough as widening the boundary itself, not a
//! data crossing, so it does not belong in this enum at all. Each capability
//! here is **deny-by-default**, crosses only by an explicit, disclosed,
//! individually-revocable grant, and there is no sixth "everything" lane.

use serde::{Deserialize, Serialize};

/// The exhaustive set of `terem-gate` bridges. Ordered + hashable so the
/// consent ledger can key its per-capability state on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Capability {
    /// A one-shot clipboard payload relayed across the boundary.
    Clipboard,
    /// The single, operator-chosen, path-scoped host directory shared into
    /// the guest (`sharedFolder` in the design docs' schema; `virtiofs`/9p
    /// when open). Carries a red-team-fixed constraint no other capability
    /// does: the `hostPath` must never overlap Terem's own state/audit/
    /// `WINEPREFIX` directories -- enforced at mint time by [`crate::paths`],
    /// never left to the caller to remember.
    SharedFolder,
    /// The standing network-reach rail: NAT-isolated (default, closed to the
    /// LAN) vs. bridged onto the host's real LAN (the consent-gated
    /// escalation).
    Network,
    /// One named USB device passed through by vendor:product ID + serial --
    /// never "all USB". See [`USB_IDENTITY_SPOOFABLE_CAVEAT`]: this identity
    /// is a convenience allowlist, not a cryptographic device identity.
    Usb,
    /// Guest audio, playback and capture independently gated.
    Audio,
}

impl Capability {
    /// Every bridge, in a stable order -- the deny-by-default panel enumerates
    /// exactly these five and no more.
    pub const ALL: [Capability; 5] = [
        Capability::Clipboard,
        Capability::SharedFolder,
        Capability::Network,
        Capability::Usb,
        Capability::Audio,
    ];

    /// The stable machine key (matches the `terem-gate` state-schema crossing
    /// names in `02-security-consent-privacy.md` SS3).
    pub fn key(self) -> &'static str {
        match self {
            Capability::Clipboard => "clipboard",
            Capability::SharedFolder => "sharedFolder",
            Capability::Network => "network",
            Capability::Usb => "usbDevice",
            Capability::Audio => "audio",
        }
    }

    /// A plain-language label for the crossing prompt.
    pub fn label(self) -> &'static str {
        match self {
            Capability::Clipboard => "clipboard",
            Capability::SharedFolder => "a shared folder",
            Capability::Network => "the bridged LAN",
            Capability::Usb => "a USB device",
            Capability::Audio => "audio",
        }
    }

    /// An honest, capability-specific caveat to surface in the same consent
    /// prompt that opens this lane -- `None` when there is nothing beyond the
    /// generic "this is a hole you opened on purpose" framing. Only
    /// [`Capability::Usb`] carries one today (the BadUSB spoofability caveat);
    /// wired as a method, not a doc comment, so a real consent UI can render
    /// it, not just a source-reader.
    pub fn caveat(self) -> Option<&'static str> {
        match self {
            Capability::Usb => Some(USB_IDENTITY_SPOOFABLE_CAVEAT),
            _ => None,
        }
    }
}

/// **Red-team fix (b).** A passed-through USB device is identified by
/// vendor:product ID + serial -- the closest thing to a stable identity
/// QEMU's `-device usb-host` exposes, and strictly better than "all USB."
/// **This identity is firmware-reported and spoofable, not hardware-fused.**
/// A BadUSB-class device -- a reprogrammed USB microcontroller, or any device
/// whose firmware simply lies about its own descriptor -- can present any
/// vendor:product:serial triple it likes, including one already on an
/// operator's allowlist. A `terem-gate` USB grant therefore authorizes "the
/// device that currently claims this identity," never "one specific,
/// unforgeable piece of silicon." Treat vendor:product:serial allowlisting as
/// an audit-trail convenience against accidental/casual device swaps, not as
/// a cryptographic device identity or a defense against a deliberately
/// spoofed BadUSB peripheral -- the same honest caveat every USB-allowlist
/// product must carry, never softened in UI copy.
pub const USB_IDENTITY_SPOOFABLE_CAVEAT: &str = "USB device identity (vendor:product:serial) is firmware-reported and spoofable by a BadUSB-class device -- this is an allowlist convenience against accidental device swaps, not a cryptographic device identity, and not a defense against a deliberately spoofed peripheral.";

/// One USB device's allowlisted identity: vendor ID, product ID, and serial --
/// never a wildcard, never "all USB" (`B-sandbox-consent.md` SS2.3). See
/// [`USB_IDENTITY_SPOOFABLE_CAVEAT`] for the honest limit of what this
/// identity actually proves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbDeviceId {
    pub vendor_id: u16,
    pub product_id: u16,
    pub serial: String,
}

impl UsbDeviceId {
    pub fn new(vendor_id: u16, product_id: u16, serial: impl Into<String>) -> Self {
        UsbDeviceId {
            vendor_id,
            product_id,
            serial: serial.into(),
        }
    }

    /// A `vendor:product:serial` string for logs/audit -- attribution, not a
    /// claim of unforgeability (see the type-level caveat).
    pub fn label(&self) -> String {
        format!(
            "{:04x}:{:04x}:{}",
            self.vendor_id, self.product_id, self.serial
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usb_caveat_names_badusb_and_spoofable_plainly() {
        let c = Capability::Usb.caveat().expect("usb carries a caveat");
        assert!(c.contains("spoofable"));
        assert!(c.contains("BadUSB"));
        assert!(c.contains("not a cryptographic device identity"));
    }

    #[test]
    fn only_usb_carries_a_caveat() {
        for cap in Capability::ALL {
            if cap == Capability::Usb {
                assert!(cap.caveat().is_some());
            } else {
                assert!(cap.caveat().is_none());
            }
        }
    }

    #[test]
    fn usb_device_label_is_vendor_product_serial() {
        let d = UsbDeviceId::new(0x1234, 0xabcd, "SN-1");
        assert_eq!(d.label(), "1234:abcd:SN-1");
    }

    #[test]
    fn exactly_five_bridges_no_widen_rail_here() {
        // GPU passthrough (`widen.gpuPassthrough`) is categorically NOT a
        // bridge (B-sandbox-consent.md SS2.4) and must never appear in this
        // enum -- this test is the tripwire if someone tries to add it here.
        assert_eq!(Capability::ALL.len(), 5);
        let keys: Vec<&str> = Capability::ALL.iter().map(|c| c.key()).collect();
        assert_eq!(
            keys,
            vec!["clipboard", "sharedFolder", "network", "usbDevice", "audio"]
        );
    }
}
