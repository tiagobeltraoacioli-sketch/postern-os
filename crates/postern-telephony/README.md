# postern-telephony — carrier SMS + cellular calls for Postern OS Mobile

A Postern Labs product core (MIT OR Apache-2.0). The shared engine behind two
apps on the privacy Linux phone:

- **Postern SMS** (`sms::SmsService`) — send/receive SMS **via the mobile
  operator** (modem/SIM), MMS via mmsd-tng (phase 2).
- **Postern Dialer** (`voice::VoiceService`) — cellular/PSTN voice calls:
  dial / ring / accept / hang up / DTMF + an encrypted call log.

Design spec: `docs/specs/POSTERN-TELEPHONY.md` (architecture, privacy ledger,
license table, the video-call verdict).

## How it works

A **fresh MIT/Apache D-Bus client** to the Linux-phone telephony daemons — the
same stack postmarketOS/Mobian use:

| Daemon (GPL, system service) | D-Bus API we consume | For |
|---|---|---|
| ModemManager | `.Modem.Messaging` / `.Sms` | SMS send/receive |
| ModemManager | `.Modem.Voice` / `.Call` | voice calls, DTMF |
| mmsd-tng | `org.ofono.mms` | MMS (phase 2, stubbed) |
| callaudiod | `org.mobian_project.CallAudio` | in-call audio routing |

GPL daemons are consumed **over D-Bus IPC only** (process boundary — like
syscalls into the GPL kernel): no fork, no embed, passes the repo's
permissive-license rule. We do **not** fork GPL clients (GNOME Calls, Chatty);
this client is written fresh, mirroring the roadmap's messenger rule.

Local history (messages + call log) persists **only AEAD-sealed** — the
canonical `postern-core` seal (XChaCha20-Poly1305, Argon2id/TEE key), same
engine as `postern-vault`. See `store::SealedTelephonyStore`.

## Honesty — status & limits

- **Carrier SMS/voice is NOT private on the wire.** Plaintext SMS to the
  operator, lawful intercept, SS7, tower-level location, IMEI/IMSI. This crate
  hardens the *device side only*; anything sensitive belongs in the E2EE
  Matrix messenger (`postern-messenger`). The UI must label the transport.
- **Needs a real phone to run.** Compiles + unit-tests everywhere; connecting
  requires Linux + system bus + ModemManager + modem + SIM (and a device port
  with working VoLTE/audio). `SmsService::connect()` returns `NoModem`
  elsewhere — by design, not a mock.
- **Verified on a dev host:** `cargo check` / `cargo test` — models, codec,
  encrypted-store roundtrips (seal/open, tamper, wrong-key, no-plaintext-leak).
- **Not verified yet (device required):** every D-Bus call against a live
  ModemManager; exact mmsd-tng signatures (pin the daemon version); call-audio
  UCM routing per device; VoLTE provisioning.
- **Stubs, clearly marked:** MMS send flow (`mms::send_mms_stub`), oFono
  backend (not started — ModemManager first), contact names, notifications,
  the touch UI (future layer, like the wallet UI).
- **Not in the workspace yet:** self-contained on purpose (own empty
  `[workspace]` table). To adopt: add `crates/postern-telephony` to the root
  members and delete that table. Also enable ModemManager (+ mmsd-tng,
  callaudiod) in `os/mobile.nix` — not edited here.

## Build

```bash
cd crates/postern-telephony
cargo check            # full, incl. D-Bus layer (compiles on any OS)
cargo test             # pure core: models + encrypted store
cargo check --no-default-features   # store/models only, zero async deps
```
