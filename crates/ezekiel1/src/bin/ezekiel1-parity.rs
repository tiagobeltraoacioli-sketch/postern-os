//! Native half of the WASM↔native parity harness.
//!
//! Reads `wasm/fixtures.json`, runs **every** case through the crate's decision
//! API ([`ezekiel1::api`]) — the exact same functions the `#[wasm_bindgen]`
//! surface calls — and prints the results as one JSON object on stdout. The
//! Node harness (`wasm/parity.mjs`) runs the identical fixtures through the
//! compiled WASM module and asserts its output equals this. Any divergence is a
//! parity failure.
//!
//! Usage: `cargo run -p ezekiel1 --bin ezekiel1-parity [path/to/fixtures.json]`
//! (defaults to `<crate>/wasm/fixtures.json`).

use std::path::PathBuf;

use ezekiel1::api;
use serde_json::{json, Value};

fn main() {
    let path = std::env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("wasm/fixtures.json")
    });
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read fixtures {}: {e}", path.display()));
    let fx: Value = serde_json::from_str(&text).expect("fixtures.json is valid JSON");

    let policies = &fx["policies"];
    let mut evaluate = serde_json::Map::new();
    for c in fx["evaluate"].as_array().expect("evaluate array") {
        let toml = policies[c["policy"].as_str().unwrap()]
            .as_str()
            .expect("referenced policy exists");
        let out = api::evaluate_json(
            toml,
            c["subject"].as_str().unwrap(),
            c["resource"].as_str().unwrap(),
            c["context"].as_str().unwrap(),
            c["action"].as_str().unwrap(),
            c["now"].as_str().unwrap(),
        );
        evaluate.insert(c["name"].as_str().unwrap().to_string(), Value::String(out));
    }

    let mut blp = serde_json::Map::new();
    for c in fx["blp"].as_array().expect("blp array") {
        let s = c["subject_level"].as_u64().unwrap() as u32;
        let r = c["resource_level"].as_u64().unwrap() as u32;
        let v = match c["fn"].as_str().unwrap() {
            "read" => api::blp_may_read(s, r),
            "write" => api::blp_may_write(s, r),
            other => panic!("unknown blp fn {other:?}"),
        };
        blp.insert(c["name"].as_str().unwrap().to_string(), Value::Bool(v));
    }

    let mut wall = serde_json::Map::new();
    for c in fx["wall"].as_array().expect("wall array") {
        let classes = serde_json::to_string(&c["classes"]).unwrap();
        let history = serde_json::to_string(&c["history"]).unwrap();
        let barred = api::wall_barred_json(&classes, &history, c["target"].as_str().unwrap())
            .expect("fixture wall JSON parses");
        wall.insert(c["name"].as_str().unwrap().to_string(), Value::Bool(barred));
    }

    let result = json!({ "evaluate": evaluate, "blp": blp, "wall": wall });
    println!("{}", serde_json::to_string_pretty(&result).unwrap());
}
