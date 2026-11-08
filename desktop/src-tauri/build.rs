fn main() {
    // Best-effort: surface a build-time `POSTERN_NODE_SHA256` to `option_env!`
    // in main.rs (`node_integrity_pin`) as a DEFAULT pin, via `cargo:rustc-env`.
    //
    // HONESTY / KNOWN LIMIT: in practice this default did NOT reliably embed
    // under `cargo tauri build` in this toolchain (cargo's fingerprint doesn't
    // always recompile main.rs when only a build-script `rustc-env` changes), so
    // the shipped app should be treated as having NO baked default pin. The
    // AUTHORITATIVE, always-working way to pin is the RUNTIME env: launch with
    // `POSTERN_NODE_SHA256=<sha>` — main.rs reads the process env FIRST (before
    // this option_env fallback), and an empty value disables the gate. This
    // block is kept as a harmless best-effort default and documents the caveat.
    println!("cargo:rerun-if-env-changed=POSTERN_NODE_SHA256");
    if let Ok(pin) = std::env::var("POSTERN_NODE_SHA256") {
        if !pin.trim().is_empty() {
            println!("cargo:rustc-env=POSTERN_NODE_SHA256={pin}");
        }
    }
    tauri_build::build()
}
