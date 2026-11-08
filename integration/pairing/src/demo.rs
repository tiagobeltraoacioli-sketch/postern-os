// SPDX-License-Identifier: MIT OR Apache-2.0
//! An end-to-end walkthrough of the whole v1 ceremony **over the stubbed
//! loopback transport** — no sockets, no network. This is the honest "it
//! compiles and the pieces fit" demonstration for Dev2/Dev3/Dev4, and the shape
//! a real LAN transport would drive.
//!
//! It wires: [`Pairing::begin_desktop`] -> QR bytes -> [`Pairing::scan_desktop_qr`]
//! -> [`PairingInit`] bytes -> [`DesktopPending::accept`] -> SAS compare ->
//! [`SasConfirm::confirm_sas`] -> two [`Channel`]s exchanging opaque frames
//! across a [`LoopbackPair`].
//!
//! [`Pairing::begin_desktop`]: crate::pairing::Pairing::begin_desktop
//! [`Pairing::scan_desktop_qr`]: crate::pairing::Pairing::scan_desktop_qr
//! [`PairingInit`]: crate::pairing::PairingInit
//! [`DesktopPending::accept`]: crate::pairing::DesktopPending::accept
//! [`SasConfirm::confirm_sas`]: crate::pairing::SasConfirm::confirm_sas
//! [`Channel`]: crate::channel::Channel
//! [`LoopbackPair`]: crate::transport::LoopbackPair

use crate::pairing::{Pairing, PairingError, PairingInit, QrPayload};
use crate::record::Role;
use crate::transport::{LoopbackPair, Transport};

/// Run the full pairing ceremony over an in-memory duplex and, on success,
/// carry one request + reply across the resulting encrypted channel. Returns
/// the plaintext the terminal received (should equal `demo_request`).
///
/// `human_confirms_sas` models the mandatory human step: pass `false` to see the
/// fail-closed abort.
pub fn pair_and_talk(
    demo_request: &[u8],
    human_confirms_sas: bool,
) -> Result<Vec<u8>, PairingError> {
    // The two devices' long-term identity public keys (opaque to this crate).
    let desktop_identity = b"desktop-identity-pub".to_vec();
    let phone_identity = b"phone-identity-pub".to_vec();

    // 1. Desktop generates the ephemeral anchor and shows the QR.
    let (pending, qr) = Pairing::begin_desktop(
        "Tiago's ThinkPad",
        "192.168.1.20:47001",
        desktop_identity,
    );

    // 2. QR travels screen -> camera (out of band). Serialize/parse to prove the
    //    wire form round-trips.
    let qr_bytes = qr.to_bytes();
    let scanned = QrPayload::from_bytes(&qr_bytes)?;

    // 3. Phone pins the anchor, encapsulates, derives its SAS, and replies.
    let (phone_confirm, init) =
        Pairing::scan_desktop_qr(&scanned, "Tiago's Pixel", phone_identity)?;

    // 4. The PairingInit travels over the (unauthenticated) transport.
    let (mut phone_link, mut desk_link) = LoopbackPair::new();
    phone_link
        .send(&init.to_bytes())
        .map_err(|e| PairingError::Hybrid(hybrid_err(e)))?;
    let init_bytes = desk_link
        .recv()
        .map_err(|e| PairingError::Hybrid(hybrid_err(e)))?;
    let init_parsed = PairingInit::from_bytes(&init_bytes)?;

    // 5. Desktop decapsulates and derives its SAS.
    let desk_confirm = pending.accept(&init_parsed)?;

    // The human compares both 6-digit codes. With no MITM they match.
    debug_assert!(phone_confirm.sas().matches(desk_confirm.sas()));

    // 6. Fail-closed human confirmation on BOTH devices.
    let (phone_rec, mut phone_ch) = phone_confirm.confirm_sas(human_confirms_sas)?;
    let (desk_rec, mut desk_ch) = desk_confirm.confirm_sas(human_confirms_sas)?;
    debug_assert_eq!(phone_rec.role, Role::Custodian);
    debug_assert_eq!(desk_rec.role, Role::Terminal);

    // 7. Talk: the desktop asks, the phone would approve upstream. Here we just
    //    carry an opaque request frame across the encrypted channel.
    let frame = desk_ch
        .seal_frame(demo_request)
        .map_err(|_| PairingError::MalformedQr)?;
    desk_link
        .send(&frame.to_bytes())
        .map_err(|e| PairingError::Hybrid(hybrid_err(e)))?;

    let wire = phone_link
        .recv()
        .map_err(|e| PairingError::Hybrid(hybrid_err(e)))?;
    let frame = crate::channel::Frame::from_bytes(&wire).map_err(|_| PairingError::MalformedQr)?;
    let plaintext = phone_ch.open_frame(&frame).map_err(|_| PairingError::MalformedQr)?;
    Ok(plaintext.to_vec())
}

// The demo maps a transport error into the crate's error space without adding a
// public variant just for the walkthrough.
fn hybrid_err(_e: crate::transport::TransportError) -> crate::hybrid::HybridError {
    crate::hybrid::HybridError::KemCiphertext
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_pairs_and_carries_a_request() {
        let got = pair_and_talk(b"consiglio:wallet-login:v1 challenge", true).unwrap();
        assert_eq!(got, b"consiglio:wallet-login:v1 challenge");
    }

    #[test]
    fn demo_fails_closed_without_sas() {
        assert!(matches!(
            pair_and_talk(b"anything", false),
            Err(PairingError::SasNotConfirmed)
        ));
    }
}
