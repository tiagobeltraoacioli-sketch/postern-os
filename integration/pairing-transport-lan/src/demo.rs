// SPDX-License-Identifier: MIT OR Apache-2.0
//! The honest "it fits together over a real socket" walkthrough: the **whole**
//! `postern-pairing` ceremony driven across a live localhost TCP connection via
//! this crate's [`TcpTransport`], instead of the in-memory `LoopbackPair`.
//!
//! This is the socket-path analogue of `postern_pairing::demo::pair_and_talk`.
//! It proves the framed TCP transport carries the pairing crate's real,
//! already-sealed frames end to end: the `PairingInit` (KEM leg) on the way in,
//! and an encrypted channel [`Frame`](postern_pairing::channel::Frame) on the
//! way back. This layer never looks inside either — it is a dumb pipe.
//!
//! Two threads stand in for the two devices on one subnet; the QR crosses
//! "out of band" over an in-process channel (a camera in real life). No mDNS is
//! needed to run this — the phone dials the desktop's bound port directly, which
//! is exactly what a discovered `PeerHint.lan_hint` would supply.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::mpsc;
use std::thread;

use postern_pairing::channel::Frame;
use postern_pairing::pairing::{Pairing, PairingError, PairingInit, QrPayload};
use postern_pairing::transport::{Transport, TransportError};

use crate::tcp::{TcpTransport, TcpTransportListener};

/// Errors from the socket-driven walkthrough. Kept distinct from
/// [`PairingError`] so a transport/IO fault is never mistaken for a protocol
/// (crypto/SAS) fault.
#[derive(Debug)]
pub enum DemoError {
    Pairing(PairingError),
    Transport(TransportError),
    Io(std::io::Error),
    /// A worker thread panicked or vanished.
    Thread,
}

impl std::fmt::Display for DemoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DemoError::Pairing(e) => write!(f, "pairing: {e}"),
            DemoError::Transport(e) => write!(f, "transport: {e}"),
            DemoError::Io(e) => write!(f, "io: {e}"),
            DemoError::Thread => write!(f, "worker thread failed"),
        }
    }
}
impl std::error::Error for DemoError {}

impl From<PairingError> for DemoError {
    fn from(e: PairingError) -> Self {
        DemoError::Pairing(e)
    }
}
impl From<TransportError> for DemoError {
    fn from(e: TransportError) -> Self {
        DemoError::Transport(e)
    }
}
impl From<std::io::Error> for DemoError {
    fn from(e: std::io::Error) -> Self {
        DemoError::Io(e)
    }
}

/// Run the full v1 pairing ceremony over a real localhost TCP link and, on
/// success, carry one opaque request frame from the desktop to the phone across
/// the resulting encrypted channel. Returns the plaintext the phone recovered
/// (equal to `demo_request`).
///
/// `human_confirms_sas` models the mandatory human step: pass `false` to observe
/// the fail-closed abort ([`PairingError::SasNotConfirmed`]) on both ends.
pub fn pair_over_tcp(demo_request: &[u8], human_confirms_sas: bool) -> Result<Vec<u8>, DemoError> {
    let request = demo_request.to_vec();

    // Out-of-band channel for the desktop to hand the phone its dial address +
    // QR bytes (the "point the camera at the screen" step).
    let (tx, rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>();

    // ---- Desktop / terminal side (the anchor) --------------------------------
    let desktop = thread::spawn(move || -> Result<(), DemoError> {
        let desktop_identity = b"desktop-identity-pub".to_vec();

        // Bind first so we can advertise the real, OS-chosen port in the QR.
        let listener =
            TcpTransportListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
        let addr = listener.local_addr()?;

        // Desktop generates the ephemeral anchor + QR for this exact dial hint.
        let (pending, qr) =
            Pairing::begin_desktop("Tiago's ThinkPad", addr.to_string(), desktop_identity);

        // QR crosses out of band.
        tx.send((addr, qr.to_bytes())).map_err(|_| DemoError::Thread)?;

        // Accept the phone's TCP connection and read its PairingInit frame.
        let (mut link, _peer) = listener.accept()?;
        let init_bytes = link.recv()?;
        let init = PairingInit::from_bytes(&init_bytes)?;

        // Decapsulate, derive the SAS, then the mandatory human confirmation.
        let desk_confirm = pending.accept(&init)?;
        let (_rec, mut desk_ch) = desk_confirm.confirm_sas(human_confirms_sas)?;

        // Talk: seal the opaque request and push it down the real socket.
        let frame = desk_ch.seal_frame(&request).map_err(|_| {
            DemoError::Transport(TransportError::Backend("seal failed".into()))
        })?;
        link.send(&frame.to_bytes())?;
        Ok(())
    });

    // ---- Phone / custodian side (main thread) --------------------------------
    let (addr, qr_bytes) = rx.recv().map_err(|_| DemoError::Thread)?;
    let scanned = QrPayload::from_bytes(&qr_bytes)?;
    let phone_identity = b"phone-identity-pub".to_vec();

    let (phone_confirm, init) =
        Pairing::scan_desktop_qr(&scanned, "Tiago's Pixel", phone_identity)?;

    // Dial the desktop's advertised LAN address (what a PeerHint would carry).
    let mut link = TcpTransport::connect(addr)?;
    link.send(&init.to_bytes())?;

    // Mandatory human confirmation — fail closed if the human declines.
    let confirm_result = phone_confirm.confirm_sas(human_confirms_sas);
    let (_rec, mut phone_ch) = match confirm_result {
        Ok(v) => v,
        Err(e) => {
            // Fail closed: still join the desktop thread so it does not leak.
            let _ = link.close();
            let _ = desktop.join();
            return Err(DemoError::Pairing(e));
        }
    };

    // Receive the desktop's sealed frame and open it inside the channel.
    let wire = link.recv()?;
    let frame = Frame::from_bytes(&wire).map_err(|_| {
        DemoError::Transport(TransportError::Backend("malformed frame".into()))
    })?;
    let plaintext = phone_ch
        .open_frame(&frame)
        .map_err(|_| DemoError::Transport(TransportError::Backend("open failed".into())))?;

    // Ensure the desktop finished cleanly (propagate its errors).
    match desktop.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(DemoError::Thread),
    }

    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceremony_carries_a_request_over_real_tcp() {
        let got = pair_over_tcp(b"consiglio:wallet-login:v1 challenge", true).unwrap();
        assert_eq!(got, b"consiglio:wallet-login:v1 challenge");
    }

    #[test]
    fn ceremony_fails_closed_without_sas_over_real_tcp() {
        let err = pair_over_tcp(b"anything", false).unwrap_err();
        assert!(
            matches!(err, DemoError::Pairing(PairingError::SasNotConfirmed)),
            "expected fail-closed SasNotConfirmed, got {err:?}"
        );
    }

    #[test]
    fn loopback_path_still_works_unchanged() {
        // The LoopbackPair-compatible offline path: the stub transport in the
        // pairing crate runs the same ceremony with no sockets at all.
        let got = postern_pairing::demo::pair_and_talk(b"offline", true).unwrap();
        assert_eq!(got, b"offline");
    }
}
