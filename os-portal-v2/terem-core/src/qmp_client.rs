// SPDX-License-Identifier: MIT OR Apache-2.0
//
// DESIGN PREVIEW — written ≠ built ≠ booted. UNAUDITED. THIS MODULE SPAWNS
// NOTHING: this client is generic over any `Read + Write` and has only ever
// been exercised against in-process mock servers (a scripted in-memory
// stream and a `UnixStream::pair` thread) — **never against a live QEMU**.
// The crate's one spawn path is `crate::spawn` (gated OFF by default), and
// nothing yet wires this client to a spawned process. Product name "Terem"
// is proposed only, pending trademark clearance.

//! A minimal QMP client over any `Read + Write` — the I/O half of
//! POC-SCOPE.md §2.1's `terem_qmp` control plane, reusing the tested wire
//! types in [`crate::qmp`].
//!
//! Protocol flow implemented (QEMU's documented QMP handshake):
//!
//! 1. on connect the server sends a greeting line
//!    ([`crate::qmp::QmpGreeting`]);
//! 2. the client must negotiate with `{"execute":"qmp_capabilities"}` and
//!    get a success response before any other command is accepted;
//! 3. commands then get one response line each; the server may interleave
//!    asynchronous *event* lines (`{"event": ...}`), which this client
//!    skips while waiting for a response.
//!
//! Being generic over `S: Read + Write` is what keeps this module hermetic:
//! a future slice can hand in a real `UnixStream` connected to a
//! [`crate::spawn`]-launched QEMU, while every test here hands in an
//! in-process mock. No socket to a real VM has ever been opened by this
//! crate — even the `#[ignore]`-gated real-spawn test does not speak QMP.

use std::io::{BufRead, BufReader, Read, Write};

use serde_json::Value;

use crate::qmp::{
    parse_greeting_line, parse_response_line, QmpCommand, QmpGreeting, QmpResponse,
};

/// The capability-negotiation command name (step 2 of the handshake).
pub const QMP_CAPABILITIES_CMD: &str = "qmp_capabilities";

/// `query-status`'s answer, as reported by the server: QMP's
/// `{"running": bool, "status": "<RunState>"}` shape. Distinct from
/// [`crate::guest::GuestStatus`], which is host-side (running + pid) — QMP
/// does not know the QEMU process's pid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmRunState {
    pub running: bool,
    pub status: String,
}

/// A QMP client that has completed the greeting + capability negotiation.
///
/// Constructed only via [`QmpClient::handshake`], so a value of this type
/// is always past step 2 and ready to execute commands.
pub struct QmpClient<S: Read + Write> {
    stream: BufReader<S>,
    greeting: QmpGreeting,
}

// Manual impl so Debug does not require `S: Debug` (streams often aren't):
// shows the negotiated greeting, elides the stream.
impl<S: Read + Write> std::fmt::Debug for QmpClient<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QmpClient")
            .field("greeting", &self.greeting)
            .finish_non_exhaustive()
    }
}

/// Read one `\n`-terminated line, treating EOF as an error (QMP peers do
/// not half-close mid-conversation).
fn read_line<S: Read>(reader: &mut BufReader<S>) -> Result<String, String> {
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .map_err(|e| format!("QMP read failed: {e}"))?;
    if n == 0 {
        return Err("QMP connection closed by peer (EOF)".to_string());
    }
    Ok(line)
}

/// `true` iff `line` is an asynchronous QMP event
/// (`{"event": "...", ...}`) rather than a command response.
fn is_event_line(line: &str) -> bool {
    matches!(
        serde_json::from_str::<Value>(line.trim()),
        Ok(Value::Object(map)) if map.contains_key("event")
    )
}

impl<S: Read + Write> QmpClient<S> {
    /// Perform the connect-time handshake on `stream`: read the greeting,
    /// send `qmp_capabilities`, and require a success response.
    pub fn handshake(stream: S) -> Result<Self, String> {
        let mut reader = BufReader::new(stream);
        let greeting_line = read_line(&mut reader)?;
        let greeting = parse_greeting_line(&greeting_line)?;
        let mut client = Self { stream: reader, greeting };
        match client.execute(&QmpCommand::new(QMP_CAPABILITIES_CMD))? {
            QmpResponse::Success { .. } => Ok(client),
            QmpResponse::Error { error, .. } => Err(format!(
                "QMP capability negotiation refused: {}: {}",
                error.class, error.desc
            )),
        }
    }

    /// The greeting the server sent on connect.
    pub fn greeting(&self) -> &QmpGreeting {
        &self.greeting
    }

    /// Send one command line and read its response line, skipping any
    /// asynchronous event lines the server interleaves.
    pub fn execute(&mut self, cmd: &QmpCommand) -> Result<QmpResponse, String> {
        let line = cmd.to_wire_line()?;
        let raw = self.stream.get_mut();
        raw.write_all(line.as_bytes())
            .map_err(|e| format!("QMP write failed: {e}"))?;
        raw.flush().map_err(|e| format!("QMP flush failed: {e}"))?;
        loop {
            let line = read_line(&mut self.stream)?;
            if is_event_line(&line) {
                continue; // async event, not our response
            }
            return parse_response_line(&line);
        }
    }

    /// `{"execute":"query-status"}` → the guest's [`VmRunState`]
    /// (POC-SCOPE §2.1's liveness probe).
    pub fn query_status(&mut self) -> Result<VmRunState, String> {
        match self.execute(&QmpCommand::query_status())? {
            QmpResponse::Success { ret, .. } => {
                let running = ret
                    .get("running")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| format!("query-status return lacks bool 'running': {ret}"))?;
                let status = ret
                    .get("status")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("query-status return lacks string 'status': {ret}"))?
                    .to_string();
                Ok(VmRunState { running, status })
            }
            QmpResponse::Error { error, .. } => {
                Err(format!("query-status failed: {}: {}", error.class, error.desc))
            }
        }
    }

    /// `{"execute":"system_powerdown"}` → graceful ACPI stop request
    /// (POC-SCOPE §2.1's graceful stop). Success means the request was
    /// accepted, not that the guest has already halted.
    pub fn system_powerdown(&mut self) -> Result<(), String> {
        match self.execute(&QmpCommand::system_powerdown())? {
            QmpResponse::Success { .. } => Ok(()),
            QmpResponse::Error { error, .. } => Err(format!(
                "system_powerdown failed: {}: {}",
                error.class, error.desc
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    //! Two mock strategies, neither involving any real QEMU or any process:
    //!
    //! * `ScriptedStream` — a purely in-memory `Read + Write` whose read
    //!   side replays a pre-scripted server transcript and whose write side
    //!   captures the client's exact bytes for assertion. Deterministic,
    //!   thread-free, std-only.
    //! * a `UnixStream::pair` with a mock QMP server on a thread that
    //!   actually parses each command and answers it — the closest
    //!   in-process approximation of the real socket flow (macOS-safe).

    use super::*;
    use serde_json::json;
    use std::io::{self, Cursor};

    const GREETING: &str = concat!(
        r#"{"QMP": {"version": {"qemu": {"micro": 0, "minor": 0, "major": 8}, "package": ""}, "capabilities": ["oob"]}}"#,
        "\n"
    );
    const OK: &str = "{\"return\":{}}\n";
    const STATUS_RUNNING: &str =
        "{\"return\":{\"running\":true,\"singlestep\":false,\"status\":\"running\"}}\n";

    /// In-memory `Read + Write`: reads replay `script`, writes accumulate.
    struct ScriptedStream {
        script: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl ScriptedStream {
        fn new(server_lines: &[&str]) -> Self {
            Self {
                script: Cursor::new(server_lines.concat().into_bytes()),
                written: Vec::new(),
            }
        }
    }

    impl Read for ScriptedStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.script.read(buf)
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn handshake_then_status_then_powerdown_exact_wire_bytes() {
        let stream = ScriptedStream::new(&[GREETING, OK, STATUS_RUNNING, OK]);
        let mut client = QmpClient::handshake(stream).expect("handshake should succeed");
        assert_eq!(client.greeting().qmp.capabilities, vec!["oob".to_string()]);

        let state = client.query_status().expect("query-status should succeed");
        assert_eq!(state, VmRunState { running: true, status: "running".to_string() });

        client.system_powerdown().expect("system_powerdown should succeed");

        // The client's exact wire bytes, in order.
        let written = String::from_utf8(client.stream.into_inner().written).unwrap();
        assert_eq!(
            written,
            "{\"execute\":\"qmp_capabilities\"}\n\
             {\"execute\":\"query-status\"}\n\
             {\"execute\":\"system_powerdown\"}\n"
        );
    }

    #[test]
    fn async_event_lines_are_skipped_while_awaiting_response() {
        // Server interleaves a SHUTDOWN event before the powerdown response.
        let event = "{\"event\":\"SHUTDOWN\",\"data\":{\"guest\":true},\
                     \"timestamp\":{\"seconds\":1,\"microseconds\":2}}\n";
        let stream = ScriptedStream::new(&[GREETING, OK, event, OK]);
        let mut client = QmpClient::handshake(stream).unwrap();
        client.system_powerdown().expect("event line must be skipped, not misparsed");
    }

    #[test]
    fn refused_capability_negotiation_fails_handshake() {
        let refusal = "{\"error\":{\"class\":\"GenericError\",\"desc\":\"nope\"}}\n";
        let err = QmpClient::handshake(ScriptedStream::new(&[GREETING, refusal])).unwrap_err();
        assert!(err.contains("capability negotiation refused"), "unexpected error: {err}");
        assert!(err.contains("GenericError"), "unexpected error: {err}");
    }

    #[test]
    fn command_error_responses_are_reported_not_panicked() {
        let cmd_err =
            "{\"error\":{\"class\":\"CommandNotFound\",\"desc\":\"The command has not been found\"}}\n";
        let stream = ScriptedStream::new(&[GREETING, OK, cmd_err]);
        let mut client = QmpClient::handshake(stream).unwrap();
        let err = client.query_status().unwrap_err();
        assert!(err.contains("CommandNotFound"), "unexpected error: {err}");
    }

    #[test]
    fn garbage_greeting_and_eof_are_errors() {
        // Not a greeting at all.
        assert!(QmpClient::handshake(ScriptedStream::new(&["{}\n"])).is_err());
        // Empty stream: EOF before greeting.
        let err = QmpClient::handshake(ScriptedStream::new(&[])).unwrap_err();
        assert!(err.contains("EOF"), "unexpected error: {err}");
        // Greeting but then EOF before the negotiation response.
        assert!(QmpClient::handshake(ScriptedStream::new(&[GREETING])).is_err());
    }

    #[test]
    fn malformed_status_return_is_an_error() {
        let bad = "{\"return\":{\"status\":\"running\"}}\n"; // no "running" bool
        let stream = ScriptedStream::new(&[GREETING, OK, bad]);
        let mut client = QmpClient::handshake(stream).unwrap();
        let err = client.query_status().unwrap_err();
        assert!(err.contains("running"), "unexpected error: {err}");
    }

    /// A mock QMP *server* that actually parses each command line and
    /// answers it, over a real (in-process) unix socketpair — no QEMU, no
    /// child process, macOS-safe, std-only.
    #[cfg(unix)]
    #[test]
    fn full_flow_against_mock_server_over_unix_socketpair() {
        use std::os::unix::net::UnixStream;

        let (client_end, server_end) = UnixStream::pair().expect("socketpair");

        let server = std::thread::spawn(move || {
            let mut reader = BufReader::new(server_end.try_clone().expect("clone"));
            let mut writer = server_end;
            writer.write_all(GREETING.as_bytes()).unwrap();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 {
                    break; // client hung up
                }
                let cmd: QmpCommand = serde_json::from_str(line.trim()).expect("valid command");
                let response = match cmd.execute.as_str() {
                    QMP_CAPABILITIES_CMD => json!({"return": {}}).to_string(),
                    "query-status" => {
                        json!({"return": {"running": true, "status": "running"}}).to_string()
                    }
                    "system_powerdown" => {
                        // Real QEMU emits a POWERDOWN event around the ack;
                        // emit one first to exercise event skipping.
                        let ev = json!({
                            "event": "POWERDOWN",
                            "timestamp": {"seconds": 0, "microseconds": 0}
                        })
                        .to_string();
                        writer.write_all(ev.as_bytes()).unwrap();
                        writer.write_all(b"\n").unwrap();
                        json!({"return": {}}).to_string()
                    }
                    other => json!({
                        "error": {"class": "CommandNotFound",
                                   "desc": format!("The command {other} has not been found")}
                    })
                    .to_string(),
                };
                writer.write_all(response.as_bytes()).unwrap();
                writer.write_all(b"\n").unwrap();
            }
        });

        let mut client = QmpClient::handshake(client_end).expect("handshake over socketpair");
        let state = client.query_status().expect("query-status over socketpair");
        assert_eq!(state, VmRunState { running: true, status: "running".to_string() });
        client.system_powerdown().expect("system_powerdown over socketpair");

        // Unknown commands come back as reported errors.
        let resp = client.execute(&QmpCommand::new("query-does-not-exist")).unwrap();
        assert!(matches!(resp, QmpResponse::Error { .. }));

        drop(client); // closes the client end so the server loop exits
        server.join().expect("mock server thread");
    }
}
