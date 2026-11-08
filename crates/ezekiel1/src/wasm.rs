//! The `#[wasm_bindgen]` surface for the Ezekiel 1 engine.
//!
//! Every export here is a **one-line adapter** over [`crate::api`]; there is no
//! decision logic in this file. That is the whole point: the browser console
//! calls these exports, they call `api`, and `api` is the exact code
//! `cargo test` and the native `ezekiel1-parity` binary run. The console's
//! verdicts are therefore the crate's verdicts, offline, with no reimplementation.
//!
//! Built with:
//! ```text
//! cargo build -p ezekiel1 --release --features wasm \
//!   --target wasm32-unknown-unknown
//! wasm-bindgen …/ezekiel1.wasm --out-dir … --target no-modules
//! ```
//! See `crates/ezekiel1/wasm/build.sh`.

use wasm_bindgen::prelude::*;

use crate::api;

/// Evaluate one access against a full policy (TOML). Returns the wire JSON
/// documented on [`api::evaluate_json`].
#[wasm_bindgen]
pub fn evaluate(
    policy_toml: &str,
    subject: &str,
    resource: &str,
    context: &str,
    action: &str,
    now_rfc3339: &str,
) -> String {
    api::evaluate_json(policy_toml, subject, resource, context, action, now_rfc3339)
}

/// Validate a policy (TOML). Returns `{"ok":true}` or `{"ok":false,"error":…}`.
#[wasm_bindgen]
pub fn validate_policy(policy_toml: &str) -> String {
    api::validate_json(policy_toml)
}

/// Bell-LaPadula no-read-up: may a subject at `subject_level` read a resource
/// at `resource_level`?
#[wasm_bindgen]
pub fn blp_may_read(subject_level: u32, resource_level: u32) -> bool {
    api::blp_may_read(subject_level, resource_level)
}

/// Bell-LaPadula no-write-down: may a subject at `subject_level` write a
/// resource at `resource_level`?
#[wasm_bindgen]
pub fn blp_may_write(subject_level: u32, resource_level: u32) -> bool {
    api::blp_may_write(subject_level, resource_level)
}

/// Brewer-Nash Chinese wall: does the wall bar `target` given the subject's
/// history? `classes_json` = `[{"name":…,"members":[…]}]`, `history_json` =
/// `["…"]`. Returns `true` iff barred. Throws only on malformed JSON.
#[wasm_bindgen]
pub fn wall_barred(classes_json: &str, history_json: &str, target: &str) -> Result<bool, JsError> {
    api::wall_barred_json(classes_json, history_json, target).map_err(|e| JsError::new(&e))
}

/// The crate version this WASM module was built from — so the console can show
/// exactly which engine it is running.
#[wasm_bindgen]
pub fn engine_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
