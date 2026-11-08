//! **Postern Dialer** — the cellular voice-call app core.
//!
//! Dial, ring, accept, hang up, DTMF: circuit-switched/VoLTE calls through the
//! modem via ModemManager's `Modem.Voice` + `Call` D-Bus objects, with audio
//! routing delegated to callaudiod ([`crate::audio`]). The call log persists
//! only in the encrypted store.
//!
//! Real client code, device-required at runtime (see crate honesty note):
//! whether a given modem actually delivers calls also depends on the device
//! port (VoLTE provisioning, audio UCM profiles) — pure bring-up territory.
//!
//! Privacy honesty: cellular voice is carrier-mediated — number, time,
//! duration, cell location are always visible to the operator (and lawful
//! intercept). We harden the local side; for private calls the UI points to
//! the Matrix messenger's E2EE calls.

use crate::audio::{CallAudioProxy, MODE_CALL, MODE_DEFAULT};
use crate::mm::{CallProxy, VoiceProxy};
use crate::number::{is_emergency_number, normalize_dial_string};
use crate::sms::first_modem;
use crate::store::TelephonyStore;
use crate::types::{CallOutcome, CallRecord, CallState, Direction};
use crate::TelephonyError;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use zbus::zvariant::{OwnedObjectPath, Value};
use zbus::Connection;

/// The dialer's service handle: one modem's voice surface.
pub struct VoiceService {
    conn: Connection,
    modem: OwnedObjectPath,
}

/// A live call the in-call UI drives.
pub struct ActiveCall {
    conn: Connection,
    path: OwnedObjectPath,
    pub number: String,
    pub direction: Direction,
    started_at: u64,
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl VoiceService {
    /// Connect to the system bus and bind the first modem (device required).
    pub async fn connect() -> Result<Self, TelephonyError> {
        let conn = Connection::system().await?;
        let modem = first_modem(&conn).await?;
        Ok(Self { conn, modem })
    }

    async fn voice(&self) -> Result<VoiceProxy<'_>, TelephonyError> {
        Ok(VoiceProxy::builder(&self.conn).path(self.modem.clone())?.build().await?)
    }

    async fn call_proxy(&self, path: &OwnedObjectPath) -> Result<CallProxy<'_>, TelephonyError> {
        Ok(CallProxy::builder(&self.conn).path(path.clone())?.build().await?)
    }

    /// Switch the device audio path in/out of voice-call mode (callaudiod).
    /// Best-effort: on devices without callaudiod this fails and the device
    /// port must route audio another way — surfaced, never silently ignored.
    async fn set_call_audio(&self, in_call: bool) -> Result<(), TelephonyError> {
        let audio = CallAudioProxy::new(&self.conn).await?;
        audio.select_mode(if in_call { MODE_CALL } else { MODE_DEFAULT }).await?;
        Ok(())
    }

    /// Place an outgoing call: create the call object, start it (dial), and
    /// switch audio to call mode.
    ///
    /// Safety gates, both FAIL CLOSED:
    /// - `number` must normalize to a strict `+`-and-digits dial string
    ///   ([`normalize_dial_string`]) — otherwise [`TelephonyError::InvalidNumber`],
    ///   nothing reaches the modem.
    /// - If the modem is emergency-only, or its `EmergencyOnly` state cannot
    ///   be read, only recognized emergency numbers ([`is_emergency_number`])
    ///   may be dialed; a read failure is surfaced, never treated as
    ///   "full service".
    pub async fn dial(&self, number: &str) -> Result<ActiveCall, TelephonyError> {
        let number = normalize_dial_string(number).ok_or(TelephonyError::InvalidNumber)?;
        let voice = self.voice().await?;
        // FAIL CLOSED: a failed EmergencyOnly read must never grant full
        // dialing. Emergency numbers stay dialable either way (GSM mandates
        // 112/911 work even without a SIM); everything else is refused with
        // the reason surfaced.
        match voice.emergency_only().await {
            Ok(false) => {}
            Ok(true) if is_emergency_number(&number) => {}
            Ok(true) => {
                return Err(TelephonyError::NotReady(
                    "emergency-only: no SIM/registration".into(),
                ));
            }
            Err(_) if is_emergency_number(&number) => {}
            Err(e) => {
                return Err(TelephonyError::NotReady(format!(
                    "cannot verify emergency-only state ({e}); refusing non-emergency call"
                )));
            }
        }
        let number_v = Value::from(number.as_str());
        let mut props: HashMap<&str, &Value<'_>> = HashMap::new();
        props.insert("number", &number_v);

        let path = voice.create_call(props).await?;
        let call = self.call_proxy(&path).await?;
        call.start().await?; // ← dialing via the carrier begins here
        self.set_call_audio(true).await?;

        Ok(ActiveCall {
            conn: self.conn.clone(),
            path,
            number,
            direction: Direction::Outgoing,
            started_at: now_unix(),
        })
    }

    /// Block until an incoming call rings (ModemManager `CallAdded`), and
    /// return it un-answered — the UI then shows accept/reject.
    pub async fn next_incoming(&self) -> Result<ActiveCall, TelephonyError> {
        use futures_util::StreamExt as _;
        let voice = self.voice().await?;
        let mut added = voice.receive_call_added().await?;
        while let Some(sig) = added.next().await {
            let args = sig.args()?;
            let call = self.call_proxy(&args.path).await?;
            // MMCallDirection: 1 = incoming
            if call.direction().await? == 1 {
                let number = call.number().await.unwrap_or_default();
                return Ok(ActiveCall {
                    conn: self.conn.clone(),
                    path: args.path.clone(),
                    number,
                    direction: Direction::Incoming,
                    started_at: now_unix(),
                });
            }
        }
        Err(TelephonyError::NotReady("signal stream ended".into()))
    }

    /// Hang up everything (panic-friendly single action).
    pub async fn hangup_all(&self) -> Result<(), TelephonyError> {
        self.voice().await?.hangup_all().await?;
        self.set_call_audio(false).await
    }
}

impl ActiveCall {
    async fn proxy(&self) -> Result<CallProxy<'_>, TelephonyError> {
        Ok(CallProxy::builder(&self.conn).path(self.path.clone())?.build().await?)
    }

    /// Accept (incoming calls only).
    pub async fn accept(&self) -> Result<(), TelephonyError> {
        Ok(self.proxy().await?.accept().await?)
    }

    /// Current state, mapped to the model.
    pub async fn state(&self) -> Result<CallState, TelephonyError> {
        Ok(CallState::from_mm(self.proxy().await?.state().await?))
    }

    /// DTMF keypad during the call.
    pub async fn send_dtmf(&self, digits: &str) -> Result<(), TelephonyError> {
        Ok(self.proxy().await?.send_dtmf(digits).await?)
    }

    /// Hang up and append the outcome to the encrypted call log.
    pub async fn hangup(
        self,
        outcome: CallOutcome,
        store: &mut dyn TelephonyStore,
    ) -> Result<(), TelephonyError> {
        self.proxy().await?.hangup().await?;
        store.add_call(CallRecord {
            number: self.number.clone(),
            direction: self.direction,
            outcome,
            started_at: self.started_at,
            duration_secs: now_unix().saturating_sub(self.started_at) as u32,
        });
        Ok(())
    }
}
