// SPDX-License-Identifier: MIT OR Apache-2.0
//
// DESIGN PREVIEW — written ≠ built ≠ booted. UNAUDITED. THIS MODULE SPAWNS
// NOTHING: these are wire-framing *types* only — the I/O half lives in
// [`crate::qmp_client`], which is itself only ever exercised against
// in-process mocks. The crate's one spawn path is `crate::spawn`, gated OFF
// by default; no QMP code has ever talked to a real QEMU in CI. Product
// name "Terem" is proposed only, pending trademark clearance.

//! QMP (QEMU Machine Protocol) wire-framing types for the POC's control
//! plane — the data half of POC-SCOPE.md §2.1's `terem_qmp` passthrough.
//!
//! QMP is line-delimited JSON over a unix socket: the server sends a
//! greeting object on connect, the client sends `{"execute": ...}` command
//! objects, the server answers each with `{"return": ...}` or
//! `{"error": ...}`. These types model exactly that framing and nothing
//! more; the I/O half is [`crate::qmp_client`], which is mock-tested only.
//! The only two commands v1 *needs* are `query-status` and
//! `system_powerdown` (§2.1), and the round-trip tests below pin both.
//!
//! Interop caveat, stated honestly: these types have been tested only
//! against JSON shapes transcribed from QEMU's documented QMP examples and
//! against the in-process mock servers in [`crate::qmp_client`]'s tests —
//! **never against a live QEMU** — no test in this crate ever connects QMP
//! to a real emulator (the `#[ignore]`-gated real-spawn test does not speak
//! QMP either). The first live-socket QMP exchange remains a later slice's
//! job, on an opted-in host.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The greeting QEMU sends immediately on QMP-socket connect:
/// `{"QMP": {"version": {...}, "capabilities": [...]}}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QmpGreeting {
    #[serde(rename = "QMP")]
    pub qmp: QmpGreetingBody,
}

/// The body of [`QmpGreeting`]. `version` is kept as raw JSON — the POC
/// only needs to detect the greeting, not to version-negotiate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QmpGreetingBody {
    pub version: Value,
    pub capabilities: Vec<String>,
}

/// A client→server QMP command: `{"execute": "...", "arguments": {...}}`.
///
/// Mirrors the `terem_qmp(cmd, args)` passthrough shape of POC-SCOPE §2.1 —
/// general over any command so nothing is hand-coded per-command, with
/// helpers pinned for the two commands v1 actually needs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QmpCommand {
    pub execute: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
    /// Optional client-chosen correlation id, echoed back in the response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
}

impl QmpCommand {
    /// A command with no arguments — the shape of everything v1 needs.
    pub fn new(execute: &str) -> Self {
        Self { execute: execute.to_string(), arguments: None, id: None }
    }

    /// `{"execute": "query-status"}` — v1's liveness probe (POC-SCOPE §2.1).
    pub fn query_status() -> Self {
        Self::new("query-status")
    }

    /// `{"execute": "system_powerdown"}` — v1's graceful stop (POC-SCOPE §2.1).
    pub fn system_powerdown() -> Self {
        Self::new("system_powerdown")
    }

    /// Serialize to one QMP wire line (JSON + `\n`). Framing only — the
    /// only writer in this crate is [`crate::qmp_client::QmpClient`], which
    /// is exercised solely against in-process mocks (never a live QEMU).
    pub fn to_wire_line(&self) -> Result<String, String> {
        let mut line = serde_json::to_string(self).map_err(|e| e.to_string())?;
        line.push('\n');
        Ok(line)
    }
}

/// A server→client QMP response line: success `{"return": ...}` or failure
/// `{"error": {"class": ..., "desc": ...}}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum QmpResponse {
    Success {
        #[serde(rename = "return")]
        ret: Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<Value>,
    },
    Error {
        error: QmpError,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<Value>,
    },
}

/// The error object inside a failed QMP response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QmpError {
    pub class: String,
    pub desc: String,
}

/// Parse one QMP wire line into a [`QmpResponse`].
pub fn parse_response_line(line: &str) -> Result<QmpResponse, String> {
    serde_json::from_str(line.trim())
        .map_err(|e| format!("malformed QMP response line: {e}"))
}

/// Parse one QMP wire line into the connect-time [`QmpGreeting`].
pub fn parse_greeting_line(line: &str) -> Result<QmpGreeting, String> {
    serde_json::from_str(line.trim())
        .map_err(|e| format!("malformed QMP greeting line: {e}"))
}

#[cfg(test)]
mod tests {
    //! Round-trip tests for exactly the two commands POC v1 needs
    //! (`query-status`, `system_powerdown`), against JSON transcribed from
    //! QEMU's documented QMP examples — no live QEMU is involved.

    use super::*;
    use serde_json::json;

    #[test]
    fn query_status_command_round_trips() {
        let cmd = QmpCommand::query_status();
        let line = cmd.to_wire_line().unwrap();
        // Exact wire bytes: no spurious `arguments`/`id` keys.
        assert_eq!(line, "{\"execute\":\"query-status\"}\n");
        let back: QmpCommand = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(back, cmd);
    }

    #[test]
    fn system_powerdown_command_round_trips() {
        let cmd = QmpCommand::system_powerdown();
        let line = cmd.to_wire_line().unwrap();
        assert_eq!(line, "{\"execute\":\"system_powerdown\"}\n");
        let back: QmpCommand = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(back, cmd);
    }

    #[test]
    fn query_status_response_parses_and_round_trips() {
        // Shape from QEMU's documented query-status example.
        let wire = r#"{"return": {"running": true, "status": "running"}}"#;
        let resp = parse_response_line(wire).unwrap();
        match &resp {
            QmpResponse::Success { ret, id } => {
                assert_eq!(ret["running"], json!(true));
                assert_eq!(ret["status"], json!("running"));
                assert!(id.is_none());
            }
            QmpResponse::Error { .. } => panic!("expected success response"),
        }
        // Round trip: serialize → parse → identical value.
        let re = serde_json::to_string(&resp).unwrap();
        assert_eq!(parse_response_line(&re).unwrap(), resp);
    }

    #[test]
    fn system_powerdown_response_parses_and_round_trips() {
        // system_powerdown returns the empty object on success.
        let wire = r#"{"return": {}}"#;
        let resp = parse_response_line(wire).unwrap();
        assert_eq!(
            resp,
            QmpResponse::Success { ret: json!({}), id: None }
        );
        let re = serde_json::to_string(&resp).unwrap();
        assert_eq!(re, r#"{"return":{}}"#);
        assert_eq!(parse_response_line(&re).unwrap(), resp);
    }

    #[test]
    fn error_response_parses_and_round_trips() {
        let wire =
            r#"{"error": {"class": "CommandNotFound", "desc": "The command x has not been found"}}"#;
        let resp = parse_response_line(wire).unwrap();
        match &resp {
            QmpResponse::Error { error, id } => {
                assert_eq!(error.class, "CommandNotFound");
                assert!(error.desc.contains("not been found"));
                assert!(id.is_none());
            }
            QmpResponse::Success { .. } => panic!("expected error response"),
        }
        let re = serde_json::to_string(&resp).unwrap();
        assert_eq!(parse_response_line(&re).unwrap(), resp);
    }

    #[test]
    fn greeting_parses_and_round_trips() {
        // Shape from QEMU's documented connect-time greeting.
        let wire = r#"{"QMP": {"version": {"qemu": {"micro": 0, "minor": 0, "major": 8}, "package": ""}, "capabilities": ["oob"]}}"#;
        let greeting = parse_greeting_line(wire).unwrap();
        assert_eq!(greeting.qmp.capabilities, vec!["oob".to_string()]);
        assert_eq!(greeting.qmp.version["qemu"]["major"], json!(8));
        let re = serde_json::to_string(&greeting).unwrap();
        assert_eq!(parse_greeting_line(&re).unwrap(), greeting);
    }

    #[test]
    fn malformed_lines_are_rejected() {
        assert!(parse_response_line("not json").is_err());
        assert!(parse_greeting_line("{}").is_err());
        // A greeting is not a response and vice versa.
        assert!(parse_response_line(r#"{"QMP": {"version": {}, "capabilities": []}}"#).is_err());
    }
}
