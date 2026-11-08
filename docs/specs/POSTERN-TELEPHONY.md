# Postern Telephony — carrier SMS + cellular calls on Postern OS Mobile

A Postern Labs design spec (companion crate: `crates/postern-telephony`).
Two apps for the privacy Linux phone, judged against `PRINCIPLES.md` and the
roadmap's permissive-license rule, plus the requested verdict on FaceTime-style
video calling.

- **Postern SMS** — send/receive SMS/MMS **via the mobile operator** (the
  cellular network, through the modem/SIM) — not over IP.
- **Postern Dialer** — voice calls **via mobile telephony** (cellular/PSTN
  through the modem): dialer, in-call UI, call log.

These are the repo's **first telephony apps**: `mobile/` today ships only the
wallet (Kotlin/Android + Rust `mobile/core`), and `os/mobile.nix` is a
wallet-first phone profile. Nothing here touches the wallet scope.

---

## 1. Platform reality

Postern OS Mobile is **Mobile NixOS** (`os/mobile.nix` layered on a device
port; kernel/modem/display come from the device module). On Linux phones the
modem is owned by a system daemon, exactly as in postmarketOS/Mobian:

- **ModemManager** (`org.freedesktop.ModemManager1`, system bus) — SMS via
  `.Modem.Messaging`/`.Sms`, voice via `.Modem.Voice`/`.Call`. Our primary
  backend.
- **oFono** — the alternative daemon (some device ports prefer it). Same
  D-Bus posture; a mirror backend module is future work, not started.
- **mmsd-tng** — MMS is *not* SMS: a WAP-push notification arrives over SMS
  and the payload is fetched over HTTP from the carrier's MMSC on an MMS APN.
  mmsd-tng is the user agent that does this (exposes `org.ofono.mms`).
- **callaudiod** (`org.mobian_project.CallAudio`) — ModemManager sets up the
  call, **not** the audio path. Earpiece/speaker/mic routing is switched via
  callaudiod over PipeWire/ALSA with device-specific UCM profiles. Without
  this a call "connects" silently — a real bring-up dependency most designs
  omit.

**License posture (the load-bearing point).** All four daemons are **GPL**.
They are consumed **only over D-Bus IPC** — a process boundary, exactly like
syscalls into the GPL Linux kernel. That is neither forking nor embedding GPL
code, so it passes the repo rule (MIT/Apache-2.0/BSD only; AGPL/GPL = no fork,
no embed). What is forbidden — and what we do not do — is forking/embedding
GPL *clients* (GNOME Calls, Chatty). Per the roadmap's own rule for the
messenger ("build a fresh Apache/MIT client — never fork"), `postern-telephony`
is a **fresh MIT OR Apache-2.0 client**, written from the daemons' documented
D-Bus APIs, using `zbus` (MIT, pure Rust, no libdbus link).

```
 Postern SMS UI          Postern Dialer UI      (touch layer — future,
        │                        │               like the wallet UI)
        └───────┬────────────────┘
        postern-telephony  (MIT OR Apache-2.0, this spec's crate)
          ├─ sms::SmsService      ─D-Bus→ ModemManager Messaging/Sms   (GPL daemon)
          ├─ mms proxies (ph. 2)  ─D-Bus→ mmsd-tng org.ofono.mms       (GPL daemon)
          ├─ voice::VoiceService  ─D-Bus→ ModemManager Voice/Call      (GPL daemon)
          ├─ audio proxies        ─D-Bus→ callaudiod                   (GPL daemon)
          └─ store::SealedTelephonyStore  (postern-core AEAD, vault key)
                              │
                    modem firmware / SIM / carrier
```

---

## 2. Postern SMS — the carrier-messaging app

**Scope v1:** plain SMS send/receive, threaded by counterparty number,
history in the encrypted store, incoming-message watch loop. **Phase 2:** MMS
via mmsd-tng (attachments through the hygiene scrubber before send — EXIF/GPS
stripped by default, per `postern-hygiene`'s ethos).

Flows (implemented in `sms.rs` against real D-Bus proxies):

- **Send:** `Messaging.Create({number, text})` → `Sms.Send()` → append the
  outgoing message to the encrypted store. The `Send()` call is the moment
  plaintext leaves for the operator — the code comments say so.
- **Receive:** subscribe to `Messaging.Added(path, received=true)` → read
  `Sms` properties (number/text/state/timestamp) → seal into the store →
  notify the UI.
- **Startup sync:** `Messaging.List()` → import → then messages can be
  deleted from the *unencrypted* modem/SIM storage so the only at-rest copy
  is the sealed one (user-controlled setting; default on).

UI rules (future layer): transport is always labeled **"Carrier SMS — not
private"**; a persistent affordance offers "move this conversation to Matrix"
when the counterparty is reachable there. No read receipts, no "typing"
beacons, no link previews (each is a metadata/telemetry leak).

## 3. Postern Dialer — the cellular calls app

**Scope v1:** dial pad, outgoing/incoming call lifecycle, DTMF, hold-and-accept
/ hangup-all, speaker + mic-mute via callaudiod, encrypted call log.
**Explicit non-goals:** call recording (never), carrier video calling (see §6),
visual voicemail (carrier-specific, later).

Flows (implemented in `voice.rs`):

- **Dial:** refuse politely if `Voice.EmergencyOnly` (no SIM/registration) →
  `Voice.CreateCall({number})` → `Call.Start()` → `callaudiod SelectMode(call)`.
- **Ring:** watch `Voice.CallAdded` → filter `Call.Direction == incoming` →
  UI accept/reject → `Call.Accept()`/`Call.Hangup()`.
- **In-call:** `Call.SendDtmf`, state via `Call.State`/`StateChanged`,
  speaker/mute via callaudiod.
- **End:** `Call.Hangup()` → append `CallRecord {number, direction, outcome,
  started_at, duration}` to the encrypted log. Duration only — audio is never
  captured.

**Emergency-call honesty:** dialing 112/911 must work even with no SIM where
the modem allows it, and emergency calls necessarily reveal location to the
network — the app must never claim otherwise, and must not route emergency
attempts through any "privacy" indirection.

## 4. Encrypted local store

`store::SealedTelephonyStore` — messages + call log persist **only** as one
AEAD-sealed blob:

- **Engine:** the canonical Postern seal from `postern-core` —
  **XChaCha20-Poly1305**, output `nonce ‖ ciphertext`, tamper-detected — the
  same engine as `postern-vault`, and the same AEAD-at-rest pattern as
  Dragoman's WebCrypto AES-GCM. (One canonical implementation repo-wide beats
  introducing a second AEAD; AES-256-GCM-class security either way.)
- **Key:** 32 bytes from the device vault — TEE-wrapped random key where the
  hardware has one; portable fallback **Argon2id** passphrase
  (`store::derive_key`, salt stored beside the blob).
- **Hygiene:** message bodies zeroized on drop; plaintext serialization
  zeroized after seal; wrong key/tamper ⇒ hard error; a leak test asserts the
  ciphertext contains neither body nor number.
- **No cloud, no sync, no backup** unless the user explicitly exports (and the
  export is itself a sealed blob). `clear()` is the panic-adjacent wipe of the
  app's own local cache (pairs with `postern-panic`'s lock-don't-wipe ethos —
  this is the user's own data, not evidence).
- v1 is a whole-blob record log (fine for SMS-scale data); paging/indexing is
  future work if history grows huge.

## 5. Honest privacy ledger

**What the carrier sees regardless of anything we do (be honest in-product):**

| Exposure | SMS | Voice |
|---|---|---|
| Content plaintext to operator | **yes** (SMS has no E2EE) | audio on carrier infrastructure, lawful-intercept accessible |
| Sender/recipient + timestamps | yes | yes (full CDRs) |
| SS7/Diameter interception & spoofing | yes | yes |
| Cell-tower location, continuously | yes | yes |
| IMEI/IMSI device identity | yes | yes |

**What Postern actually hardens (the honest value):** a minimal,
telemetry-free, local-only client — encrypted-at-rest history (§4), no cloud
backup, no analytics, no contact upload, messages deletable from modem/SIM
storage, permission-scoped D-Bus access, and UI labels that say "Carrier —
not private" while steering sensitive conversations to the E2EE Matrix
messenger. **Claim exactly this, nothing more.** A privacy phone that
pretended carrier SMS/voice were private would be lying; one that refuses to
do telephony at all isn't a phone.

## 6. Verdict — does FaceTime-style video belong in the Dialer?

**No. Video calling belongs in the Matrix messenger, not the cellular dialer.
Recommendation: keep the Dialer voice-only; ship video as Matrix E2EE calls;
add a clearly-labeled "escalate to encrypted video" bridge.**

Rationale, honestly argued:

1. **FaceTime is IP, not carrier.** FaceTime is VoIP/video over the internet
   between Apple endpoints. It only *looks* adjacent to the dialer because
   Apple owns both apps. There is no carrier leg in it.
2. **Carrier video calling is a dead end here.** The cellular equivalent
   (VoLTE/IMS video telephony, 3G-324M VT historically) is effectively
   unsupported on Linux phones — ModemManager/oFono expose no usable video-call
   API, device IMS stacks barely do voice, and even where VT works it still
   traverses the carrier (all of §5's exposures, plus video). Building the
   Dialer's video on the carrier path is building on sand, against our own
   privacy posture.
3. **The repo already has the right home.** The roadmap's Matrix messenger
   (`postern-messenger`, flagship comms) already plans voice/video via
   **matrix-rust-sdk (Apache-2.0) + libwebrtc (BSD-3), LiveKit SFU (Apache)
   for groups** — E2EE, permissive, IP-native. Duplicating a second, worse
   video stack inside the dialer splits engineering and audits across two
   codepaths for zero user gain.
4. **Licensing reinforces it.** The permissive video path (libwebrtc/LiveKit)
   is already vetted for the messenger. There is no permissive carrier-video
   client stack to borrow, and the GPL ones may not be forked anyway.
5. **User mental model & honest labeling.** Dialer = cellular/PSTN =
   "reaches any phone number, not private." Matrix = internet = "E2EE,
   private, needs data." Bolting an IP video button into the carrier dialer
   blurs exactly the boundary our honesty posture depends on — a user must
   never wonder *which network* their "call" is on.

**The bridge (do this instead):** in an active cellular call or on a contact
card, show **"Escalate to encrypted video (Matrix)"** — enabled only when the
contact has a verified Matrix binding in the local (encrypted) contact store.
Tapping it hands off to the messenger app, which places the E2EE call; the
cellular call can then be hung up. The Dialer never speaks Matrix and the
messenger never speaks ModemManager — separate apps, separate transports,
separately labeled. (Discovery via phone-number lookup on a Matrix identity
server would leak the contact graph — do NOT do that; bindings are manual/QR
or from prior Matrix contact exchange.)

## 7. License table (every named dependency)

| Component | Role | License | Verdict under repo rule |
|---|---|---|---|
| `zbus` (+ zvariant) | D-Bus client library (pure Rust) | MIT | ✅ use |
| `tokio` | async runtime for the D-Bus layer | MIT | ✅ use |
| `futures-util` | signal streams | MIT OR Apache-2.0 | ✅ use |
| `thiserror`, `zeroize` | errors / RAM hygiene | MIT OR Apache-2.0 | ✅ use |
| `postern-core` | canonical AEAD (XChaCha20-Poly1305) + Argon2id | MIT OR Apache-2.0 (in-house) | ✅ use |
| ModemManager | modem daemon (SMS/voice D-Bus API) | **GPL-2.0+** | ✅ **system service over D-Bus only** — no fork, no embed, no link |
| oFono | alternative modem daemon | **GPL-2.0** | ✅ same D-Bus-only posture (future backend) |
| mmsd-tng | MMS user agent daemon | **GPL** | ✅ D-Bus only; pin the packaged version |
| callaudiod | call-audio routing daemon | **GPL-3.0** | ✅ D-Bus only |
| GNOME Calls, Chatty | existing GPL clients | **GPL-3.0** | ❌ no fork, no embed, no UI port — concept reference only |
| matrix-rust-sdk (§6) | Matrix client SDK | Apache-2.0 | ✅ (messenger; pin versions per roadmap) |
| libwebrtc / LiveKit (§6) | IP video | BSD-3 / Apache-2.0 | ✅ (messenger, where video lives) |

Re-verify at adoption (roadmap habit): exact mmsd-tng license text + D-Bus
signature stability across releases; callaudiod's successor status in current
Mobian; LiveKit's current license.

## 8. Buildable now vs needs hardware

**Verified on the dev host (macOS, cargo 1.94.1):**
- `cargo check` — full crate incl. the zbus D-Bus layer — clean.
- `cargo check --no-default-features` — pure core (models + store) — clean.
- `cargo test` — 9/9: codec roundtrips, truncation never panics, MM enum
  mapping, store seal/open, wrong-key + tamper rejection, no-plaintext-leak,
  Argon2id determinism, clear().

**Requires a real phone (PinePhone/Librem 5-class, SIM, carrier):**
- Every D-Bus call against live ModemManager (signatures written from the MM
  1.x introspection docs — validate at bring-up).
- mmsd-tng MMS flow (APN config, MMSC fetch) — currently an honest stub
  (`mms::send_mms_stub` returns `Unimplemented`).
- callaudiod/UCM audio routing (device-port specific), VoLTE provisioning,
  emergency-call behavior.

**For the lead to wire up (deliberately not done here):**
1. Add `crates/postern-telephony` to the root `Cargo.toml` members and delete
   the crate's own empty `[workspace]` table (kept self-contained so the root
   build can't break).
2. Enable the daemons in `os/mobile.nix` (ModemManager, mmsd-tng, callaudiod;
   Mobile NixOS device ports supply modem drivers) — this spec does not edit
   the OS profile.
3. The touch UI layer (same pattern as the wallet: Rust core + UI shell), and
   the Matrix "escalate to video" handoff once `postern-messenger` grows its
   matrix-rust-sdk client.
