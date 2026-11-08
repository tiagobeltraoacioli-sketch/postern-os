//! Pure data models for messages and calls — no D-Bus, host-testable.
//!
//! These are the records the apps render and the encrypted store persists.
//! Numeric enums mirror ModemManager's `MMSmsState` / `MMCallState` values so
//! the D-Bus layer maps losslessly, but the types themselves have no zbus dep.

use zeroize::Zeroize;

// ── SMS ──────────────────────────────────────────────────────────────────────

/// Direction of a message or call, from the phone's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Incoming,
    Outgoing,
}

/// Delivery state of an SMS (mirrors ModemManager `MMSmsState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmsState {
    Unknown,
    Stored,
    Receiving,
    Received,
    Sending,
    Sent,
    SendingFailed,
}

impl SmsState {
    /// Map a ModemManager `MMSmsState` (u32 over D-Bus) to the model.
    pub fn from_mm(v: u32) -> Self {
        match v {
            1 => SmsState::Stored,
            2 => SmsState::Receiving,
            3 => SmsState::Received,
            4 => SmsState::Sending,
            5 => SmsState::Sent,
            _ => SmsState::Unknown,
        }
    }
}

/// One SMS message. `body`, `number`, and `timestamp` are wiped from RAM on
/// drop — both content and who-texted-whom metadata are treated as secret
/// *locally* (the carrier saw them in plaintext regardless; see the
/// crate-level honesty note).
#[derive(Debug, Clone)]
pub struct SmsMessage {
    /// Counterparty number as the modem reported it (E.164 when available).
    pub number: String,
    pub body: String,
    pub direction: Direction,
    pub state: SmsState,
    /// Carrier timestamp (ISO 8601 as ModemManager reports it), if known.
    pub timestamp: Option<String>,
}

impl Drop for SmsMessage {
    fn drop(&mut self) {
        self.number.zeroize();
        self.body.zeroize();
        self.timestamp.zeroize();
    }
}

// ── Voice calls ──────────────────────────────────────────────────────────────

/// Call state (mirrors ModemManager `MMCallState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    Unknown,
    Dialing,
    RingingOut,
    RingingIn,
    Active,
    Held,
    Waiting,
    Terminated,
}

impl CallState {
    /// Map a ModemManager `MMCallState` (i32 over D-Bus) to the model.
    pub fn from_mm(v: i32) -> Self {
        match v {
            1 => CallState::Dialing,
            2 => CallState::RingingOut,
            3 => CallState::RingingIn,
            4 => CallState::Active,
            5 => CallState::Held,
            6 => CallState::Waiting,
            7 => CallState::Terminated,
            _ => CallState::Unknown,
        }
    }
}

/// How a logged call ended — what the call-log UI renders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallOutcome {
    Completed,
    Missed,
    Rejected,
    Failed,
}

/// One call-log entry, persisted only in the encrypted store (never plaintext
/// on disk, never uploaded). Duration only — no audio is ever recorded.
/// The who-called-whom metadata (`number`, `started_at`, `duration_secs`) is
/// exactly what the spec's privacy ledger treats as sensitive, so it is wiped
/// from RAM on drop just like SMS content.
#[derive(Debug, Clone)]
pub struct CallRecord {
    pub number: String,
    pub direction: Direction,
    pub outcome: CallOutcome,
    /// Unix seconds at call start (device clock).
    pub started_at: u64,
    pub duration_secs: u32,
}

impl Drop for CallRecord {
    fn drop(&mut self) {
        self.number.zeroize();
        self.started_at.zeroize();
        self.duration_secs.zeroize();
    }
}

// ── minimal wire codec for the encrypted store (no serde dep, matches the
//    postern-vault length-prefixed style) ─────────────────────────────────────

fn push_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn read_str(d: &[u8], i: &mut usize) -> Option<String> {
    if *i + 4 > d.len() {
        return None;
    }
    let n = u32::from_le_bytes([d[*i], d[*i + 1], d[*i + 2], d[*i + 3]]) as usize;
    *i += 4;
    if *i + n > d.len() {
        return None;
    }
    match String::from_utf8(d[*i..*i + n].to_vec()) {
        Ok(s) => {
            *i += n;
            Some(s)
        }
        Err(e) => {
            // Invalid UTF-8 in a corrupt store: wipe the copied plaintext
            // bytes before rejecting, so the temp buffer never lingers.
            let mut bytes = e.into_bytes();
            bytes.zeroize();
            None
        }
    }
}

impl SmsMessage {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_str(&mut out, &self.number);
        push_str(&mut out, &self.body);
        out.push(matches!(self.direction, Direction::Outgoing) as u8);
        out.push(self.state as u8);
        push_str(&mut out, self.timestamp.as_deref().unwrap_or(""));
        out
    }

    pub(crate) fn decode(d: &[u8]) -> Option<SmsMessage> {
        let mut i = 0usize;
        let number = read_str(d, &mut i)?;
        let body = read_str(d, &mut i)?;
        if i + 2 > d.len() {
            return None;
        }
        let direction = if d[i] == 1 { Direction::Outgoing } else { Direction::Incoming };
        let state = SmsState::from_mm(d[i + 1] as u32);
        i += 2;
        let ts = read_str(d, &mut i)?;
        Some(SmsMessage {
            number,
            body,
            direction,
            state,
            timestamp: if ts.is_empty() { None } else { Some(ts) },
        })
    }
}

impl CallRecord {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_str(&mut out, &self.number);
        out.push(matches!(self.direction, Direction::Outgoing) as u8);
        out.push(match self.outcome {
            CallOutcome::Completed => 0,
            CallOutcome::Missed => 1,
            CallOutcome::Rejected => 2,
            CallOutcome::Failed => 3,
        });
        out.extend_from_slice(&self.started_at.to_le_bytes());
        out.extend_from_slice(&self.duration_secs.to_le_bytes());
        out
    }

    pub(crate) fn decode(d: &[u8]) -> Option<CallRecord> {
        let mut i = 0usize;
        let number = read_str(d, &mut i)?;
        if i + 2 + 8 + 4 > d.len() {
            return None;
        }
        let direction = if d[i] == 1 { Direction::Outgoing } else { Direction::Incoming };
        let outcome = match d[i + 1] {
            0 => CallOutcome::Completed,
            1 => CallOutcome::Missed,
            2 => CallOutcome::Rejected,
            _ => CallOutcome::Failed,
        };
        i += 2;
        let started_at = u64::from_le_bytes(d[i..i + 8].try_into().ok()?);
        i += 8;
        let duration_secs = u32::from_le_bytes(d[i..i + 4].try_into().ok()?);
        Some(CallRecord { number, direction, outcome, started_at, duration_secs })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sms_codec_roundtrip() {
        let m = SmsMessage {
            number: "+15551234567".into(),
            body: "meet at 6 — bring the ledger".into(),
            direction: Direction::Outgoing,
            state: SmsState::Sent,
            timestamp: Some("2026-07-09T12:00:00+00:00".into()),
        };
        let d = SmsMessage::decode(&m.encode()).unwrap();
        assert_eq!(d.number, m.number);
        assert_eq!(d.body, m.body);
        assert_eq!(d.direction, m.direction);
        assert_eq!(d.state, m.state);
        assert_eq!(d.timestamp, m.timestamp);
    }

    #[test]
    fn call_codec_roundtrip() {
        let c = CallRecord {
            number: "+15559876543".into(),
            direction: Direction::Incoming,
            outcome: CallOutcome::Missed,
            started_at: 1_780_000_000,
            duration_secs: 0,
        };
        let d = CallRecord::decode(&c.encode()).unwrap();
        assert_eq!(d.number, c.number);
        assert_eq!(d.direction, c.direction);
        assert_eq!(d.outcome, c.outcome);
        assert_eq!(d.started_at, c.started_at);
        assert_eq!(d.duration_secs, c.duration_secs);
    }

    #[test]
    fn truncated_data_is_rejected_not_panicking() {
        let m = SmsMessage {
            number: "+1555".into(),
            body: "x".into(),
            direction: Direction::Incoming,
            state: SmsState::Received,
            timestamp: None,
        };
        let enc = m.encode();
        for cut in 0..enc.len() {
            let _ = SmsMessage::decode(&enc[..cut]); // must never panic
        }
        assert!(SmsMessage::decode(&enc[..3]).is_none());
    }

    #[test]
    fn mm_state_mappings() {
        assert_eq!(SmsState::from_mm(5), SmsState::Sent);
        assert_eq!(SmsState::from_mm(99), SmsState::Unknown);
        assert_eq!(CallState::from_mm(3), CallState::RingingIn);
        assert_eq!(CallState::from_mm(-1), CallState::Unknown);
    }
}
