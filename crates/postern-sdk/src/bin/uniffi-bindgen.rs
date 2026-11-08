//! UniFFI bindings generator entrypoint for the unified Postern SDK. Invoked as
//! `cargo run -p postern-sdk --bin uniffi-bindgen -- generate --library <lib>
//! --language {kotlin,swift} ...` to emit the Kotlin/Swift host bindings for the
//! ENTIRE Postern product suite from the single compiled `postern_sdk` library.
fn main() {
    uniffi::uniffi_bindgen_main()
}
