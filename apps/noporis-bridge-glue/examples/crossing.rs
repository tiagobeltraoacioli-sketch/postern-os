// SPDX-License-Identifier: MIT OR Apache-2.0
//! A runnable walkthrough of ONE guarded crossing, printed step by step.
//!
//! SCAFFOLD / UNAUDITED. Runs entirely in one process over an in-memory loopback
//! (no sockets, no network). It drives the two personas across the tested pairing
//! channel + the deny-by-default gate, showing that nothing crosses without a
//! live near-side grant, nothing is delivered without a live far-side gate
//! `Allow`, and a kill-switch cuts the span — every crossing explicit,
//! per-capability, and revocable.
//!
//! Run: `cargo run --example crossing` from this crate's directory.

use noporis_bridge_glue::{
    BridgeError, Capability, CrossingReceiver, CrossingSender, DenyReason, Persona, ReferenceGate,
};
use postern_pairing::channel::endpoints;
use postern_pairing::hybrid::SessionKey;
use postern_pairing::transport::LoopbackPair;
use zeroize::Zeroizing;

fn line(label: &str, value: &str) {
    println!("    {label:<26} {value}");
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!("║  NoporIS — the guarded crossing (Kalinov most)   SCAFFOLD, UNAUDITED    ║");
    println!("║  a per-capability DATA crossing between two personas on ONE handset     ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝");
    println!(
        "\nNOTE: one process, in-memory loopback — no sockets, no network. The\n\
         Google-Play persona is the LESS-PRIVATE side by construction. A rooted\n\
         host defeats every boundary here. App on stock Android, never \"Postern OS\"."
    );

    // A live paired session (in reality: QR + 6-digit SAS + PairingRecord). Here we
    // stand it up directly from a session key to focus on the CROSSING.
    let sk: SessionKey = Zeroizing::new([0x42u8; 32]);
    let (mut chan_play, mut chan_clean) = endpoints(&sk);
    let paired_session_id = *chan_play.session_id();
    let (mut bearer_play, mut bearer_clean) = LoopbackPair::new();

    let now = 1_752_000_000i64;

    // Persona A: the Google-Play (less-private) side wants to hand a file to the
    // clean side. It opens ONE lane, time-boxed.
    let mut play = CrossingSender::new(&paired_session_id, Persona::GooglePlay, "this handset · clean");
    // Persona B: the clean side, guarded by the (reference stand-in for the) N-gate.
    let mut gate = ReferenceGate::new();
    let mut clean = CrossingReceiver::new(&paired_session_id, Persona::GooglePlay, Persona::Clean, ReferenceGate::new());

    println!("\n[1] Google-Play side  │  opens ONE lane (files) to the clean side for 10 min");
    play.open_lane(Capability::Files, Persona::Clean, now + 600);
    line("from world", Persona::GooglePlay.label());
    line("capability", Capability::Files.label());
    line("tier", &format!("{:?}", Capability::Files.tier()));

    println!("\n[2] Google-Play side  │  send_crossing(): fresh nonce + monotonic counter + session binding, SEALED");
    let sent = play
        .send_crossing(&mut chan_play, &mut bearer_play, Capability::Files, Persona::Clean, b"quarterly.pdf bytes", now)
        .expect("live grant → sent");
    line("counter", &sent.counter.to_string());
    line("nonce (head)", &hex::encode(&sent.req_nonce[..6]));

    println!("\n[3] Clean side (gate) │  DENY-BY-DEFAULT: the files lever is still CLOSED → nothing crosses");
    let denied = clean.receive_crossing(&mut chan_clean, &mut bearer_clean, now);
    match &denied {
        Err(BridgeError::GateDenied(DenyReason::ConsentNotAccepted)) => {
            line("result", "DENIED — first-entry consent not accepted (fail-closed)")
        }
        other => line("result", &format!("{other:?}")),
    }

    println!("\n[4] Human             │  accepts the crossing disclosure + throws the files lever");
    // Re-arm the sender (the prior frame was consumed by the failed delivery) and
    // configure the gate to now permit files.
    gate.accept_consent().open(Capability::Files);
    *clean.gate_mut() = gate;
    play.open_lane(Capability::Files, Persona::Clean, now + 600);
    let _ = play
        .send_crossing(&mut chan_play, &mut bearer_play, Capability::Files, Persona::Clean, b"quarterly.pdf bytes", now)
        .expect("live grant → sent");

    println!("\n[5] Clean side (gate) │  Allow → the payload crosses, delivered zeroizing");
    let got = clean
        .receive_crossing(&mut chan_clean, &mut bearer_clean, now)
        .expect("gate allow → delivered");
    line("delivered capability", got.capability.label());
    line("from world", got.from_persona.label());
    line("bytes", &String::from_utf8_lossy(&got.bytes));

    println!("\n[6] Kill-switch       │  cutting the span refuses all further crossings (door + keys untouched)");
    play.open_lane(Capability::Files, Persona::Clean, now + 600);
    let _ = play
        .send_crossing(&mut chan_play, &mut bearer_play, Capability::Files, Persona::Clean, b"more", now)
        .expect("sent");
    clean.gate_mut().engage_kill_switch();
    let cut = clean.receive_crossing(&mut chan_clean, &mut bearer_clean, now);
    line("result", &format!("{cut:?}"));

    println!("\n[7] Audit ledger      │  the CLEAN side's in-memory record — size + SHA-256 digest, NEVER bytes");
    for e in clean.audit().entries() {
        let r = &e.record;
        line(
            &format!("#{} {}", e.seq, r.capability.key()),
            &format!(
                "{:<22} {:>5} B  sha256={}",
                r.outcome.code(),
                r.digest.len,
                r.digest.short()
            ),
        );
    }
    line("ledger chain verifies", &clean.audit().verify().to_string());
    println!(
        "    (attribution, not confidentiality: the digest proves WHICH blob crossed,\n\
         \x20    it does not store or reveal the blob. A rooted host can forge the whole chain.)"
    );

    println!("\n╔══════════════════════════════════════════════════════════════════════╗");
    println!("║  DONE — nothing crossed without BOTH a live grant AND a live gate yes.  ║");
    println!("║  Explicit · per-capability · revocable · deny-by-default · fail-closed. ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝");
}
