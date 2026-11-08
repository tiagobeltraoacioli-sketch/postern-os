//! CI-style regression guard for `tauri.conf.json`'s `bundle` section.
//!
//! Packaging metadata is easy to accidentally weaken in a routine edit — a
//! merge that drops `createUpdaterArtifacts: false`, a copy-paste that swaps
//! the license for a copyleft one, a "just for local testing" signing
//! identity that gets left in, a trimmed `deb.depends` that ships a package
//! webkit2gtk can't actually run. None of those show up as a compile error.
//!
//! This test asserts the bundle config has not regressed from its reviewed
//! baseline:
//!   - `bundle.active` stays `true` (bundling isn't silently disabled).
//!   - `bundle.targets` stays non-empty (some target is actually produced).
//!   - `bundle.createUpdaterArtifacts` stays `false` (no updater artifacts
//!     until there's an actual update channel to serve them from).
//!   - `bundle.license` stays permissive and never turns copyleft — this is
//!     a fail-closed guard: it does not enumerate every acceptable SPDX
//!     expression, it only refuses to pass if the string contains `GPL`
//!     (which also catches `AGPL`/`LGPL` as substrings).
//!   - `bundle.macOS.signingIdentity` stays `null`, documenting the
//!     unsigned-by-design stance — a stray signing identity becomes a
//!     reviewed edit to this test, not a silent build-config drift.
//!   - `bundle.linux.deb.depends` stays non-empty (the .deb still declares
//!     its runtime deps instead of shipping an unrunnable package).
//!
//! Dependency-free (std only), same as `config_hardening.rs`, so it adds no
//! crate / `Cargo.lock` churn. This is a *regression tripwire*, not a
//! packaging or security audit: it asserts the reviewed baseline hasn't been
//! weakened, nothing more.

use std::path::PathBuf;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    let p = manifest_dir().join(rel);
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

// ── tiny, quote-literal JSON extractors, reused as-is from
// config_hardening.rs (the config file contains no escaped quotes inside the
// values we read, so this stays honest and simple) ──

/// Value of a top-level `"key": "…"` string (first match). Panics if absent.
fn json_string_value(src: &str, key: &str) -> String {
    let needle = format!("\"{key}\"");
    let after_key = src
        .find(&needle)
        .map(|i| i + needle.len())
        .unwrap_or_else(|| panic!("key {key:?} not found"));
    let colon = src[after_key..]
        .find(':')
        .map(|i| after_key + i + 1)
        .expect("':' after key");
    let open = src[colon..]
        .find('"')
        .map(|i| colon + i + 1)
        .expect("opening quote of value");
    let close = src[open..].find('"').map(|i| open + i).expect("closing quote");
    src[open..close].to_string()
}

/// String literals inside a top-level `"key": [ … ]` array. Panics if absent.
fn json_string_array(src: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{key}\"");
    let after_key = src
        .find(&needle)
        .map(|i| i + needle.len())
        .unwrap_or_else(|| panic!("key {key:?} not found"));
    let open = src[after_key..]
        .find('[')
        .map(|i| after_key + i + 1)
        .expect("'[' after key");
    let close = src[open..].find(']').map(|i| open + i).expect("']' of array");
    let body = &src[open..close];
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(q0) = rest.find('"') {
        let after = &rest[q0 + 1..];
        let q1 = after.find('"').expect("closing quote in array");
        out.push(after[..q1].to_string());
        rest = &after[q1 + 1..];
    }
    out
}

// ── small additions on top of the shared extractors above, needed because
// `bundle` mixes booleans, `null`, and nested objects that `capabilities/
// default.json` and the CSP string never did ──

/// The raw (un-parsed) JSON value text that follows a top-level `"key":`,
/// handling the value shapes this config actually uses: a quoted string, a
/// `[ … ]` array, a `{ … }` object, or a bare literal (`true`/`false`/
/// `null`). Depth-matches brackets/braces so nested objects/arrays don't
/// truncate early. Panics if the key or a closing delimiter is missing.
fn json_raw_value(src: &str, key: &str) -> String {
    let needle = format!("\"{key}\"");
    let after_key = src
        .find(&needle)
        .map(|i| i + needle.len())
        .unwrap_or_else(|| panic!("key {key:?} not found"));
    let colon = src[after_key..]
        .find(':')
        .map(|i| after_key + i + 1)
        .expect("':' after key");
    let rest = src[colon..].trim_start();
    match rest.chars().next() {
        Some('"') => {
            let close = rest[1..].find('"').expect("closing quote of value") + 1;
            rest[..=close].to_string()
        }
        Some('[') => {
            let mut depth = 0i32;
            for (i, c) in rest.char_indices() {
                match c {
                    '[' => depth += 1,
                    ']' => {
                        depth -= 1;
                        if depth == 0 {
                            return rest[..=i].to_string();
                        }
                    }
                    _ => {}
                }
            }
            panic!("no matching ']' for key {key:?}");
        }
        Some('{') => {
            let mut depth = 0i32;
            for (i, c) in rest.char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            return rest[..=i].to_string();
                        }
                    }
                    _ => {}
                }
            }
            panic!("no matching '}}' for key {key:?}");
        }
        Some(_) => {
            let end = rest
                .find([',', '\n', '}'])
                .unwrap_or(rest.len());
            rest[..end].trim().to_string()
        }
        None => panic!("no value after key {key:?}"),
    }
}

/// The `{ … }` body of a top-level `"key": { … }` object, braces stripped.
fn json_object_body(src: &str, key: &str) -> String {
    let raw = json_raw_value(src, key);
    assert!(
        raw.starts_with('{') && raw.ends_with('}'),
        "key {key:?} is not a JSON object (got `{raw}`)"
    );
    raw[1..raw.len() - 1].to_string()
}

/// Value of a top-level `"key": true|false`. Panics if absent or not a bool.
fn json_bool_value(src: &str, key: &str) -> bool {
    match json_raw_value(src, key).as_str() {
        "true" => true,
        "false" => false,
        other => panic!("key {key:?} is not a bool literal (got `{other}`)"),
    }
}

// ─────────────────────────────── bundle config ──────────────────────────────

#[test]
fn bundle_stays_active_and_produces_targets() {
    let conf = read("tauri.conf.json");
    let bundle = json_object_body(&conf, "bundle");

    assert!(
        json_bool_value(&bundle, "active"),
        "bundle.active must stay true — bundling must not be silently disabled"
    );

    // `targets` is now an explicit reviewed array (see the dedicated test
    // below), but this baseline check stays shape-agnostic — accept either a
    // string or an array and just require that it names at least one target.
    let targets_raw = json_raw_value(&bundle, "targets");
    let targets_nonempty = if targets_raw.starts_with('"') {
        !targets_raw.trim_matches('"').is_empty()
    } else if targets_raw.starts_with('[') {
        !json_string_array(&bundle, "targets").is_empty()
    } else {
        false
    };
    assert!(
        targets_nonempty,
        "bundle.targets must be a non-empty string or array; got `{targets_raw}`"
    );
}

#[test]
fn bundle_does_not_ship_updater_artifacts() {
    let conf = read("tauri.conf.json");
    let bundle = json_object_body(&conf, "bundle");

    assert!(
        !json_bool_value(&bundle, "createUpdaterArtifacts"),
        "bundle.createUpdaterArtifacts must stay false — there is no update \
         channel to serve updater artifacts from; flipping this on is a \
         reviewed, deliberate change, not a routine edit"
    );
}

#[test]
fn bundle_license_stays_permissive() {
    let conf = read("tauri.conf.json");
    let bundle = json_object_body(&conf, "bundle");
    let license = json_string_value(&bundle, "license");

    assert!(!license.trim().is_empty(), "bundle.license must not be empty");

    // Fail-closed guard: this does not enumerate every acceptable SPDX
    // expression, it only refuses a copyleft one. `GPL` as a substring also
    // catches `AGPL` and `LGPL`.
    assert!(
        !license.contains("GPL"),
        "bundle.license = `{license}` contains `GPL` — copyleft licenses \
         (GPL/AGPL/LGPL) are not permitted for this bundle; this must be a \
         deliberate, reviewed change if it is ever intentional"
    );
}

#[test]
fn macos_signing_identity_stays_unset_by_design() {
    let conf = read("tauri.conf.json");
    let bundle = json_object_body(&conf, "bundle");
    let macos = json_object_body(&bundle, "macOS");

    assert_eq!(
        json_raw_value(&macos, "signingIdentity"),
        "null",
        "bundle.macOS.signingIdentity is no longer null — this app is \
         unsigned by design (no Apple Developer ID enrolled). A stray \
         signing identity here must be a deliberate, reviewed edit, not a \
         silent drift, since it changes what Gatekeeper does with the build"
    );
}

#[test]
fn bundle_targets_are_an_explicit_reviewed_array_covering_all_three_oses() {
    let conf = read("tauri.conf.json");
    let bundle = json_object_body(&conf, "bundle");

    // The reviewed baseline moved from the catch-all string "all" to an
    // explicit array — a regression back to a string (or an empty array) is
    // a silent widening/narrowing of what gets built and must be a reviewed
    // edit to this test instead.
    let targets_raw = json_raw_value(&bundle, "targets");
    assert!(
        targets_raw.starts_with('['),
        "bundle.targets must be an explicit reviewed array, not `{targets_raw}`"
    );
    let targets = json_string_array(&bundle, "targets");
    assert!(!targets.is_empty(), "bundle.targets array must not be empty");

    let has = |names: &[&str]| names.iter().any(|n| targets.iter().any(|t| t == n));
    assert!(
        has(&["deb", "appimage"]),
        "bundle.targets must keep at least one Linux target (deb or appimage); got {targets:?}"
    );
    assert!(
        has(&["app", "dmg"]),
        "bundle.targets must keep at least one macOS target (app or dmg); got {targets:?}"
    );
    assert!(
        has(&["msi", "nsis"]),
        "bundle.targets must keep at least one Windows target (msi or nsis); got {targets:?}"
    );
}

// ───────────────────────────── package-signed.sh ────────────────────────────

#[test]
fn package_signed_script_keeps_its_gates_and_honesty_markers() {
    // Regression tripwire over package-signed.sh, NOT an audit of it: the
    // script's safety posture lives in a handful of literal strings — the
    // strict shell mode, the E2E env gate, the honesty markers, and the fact
    // that it reuses (never reimplements) the two existing signing
    // pipelines. A routine edit that drops any of them should fail here, as
    // a reviewed change, not slip through silently.
    let script = read("package-signed.sh");
    let lower = script.to_lowercase();

    assert!(
        script.contains("set -euo pipefail"),
        "package-signed.sh must keep `set -euo pipefail`"
    );
    assert!(
        script.contains("POSTERN_PACKAGING_E2E"),
        "package-signed.sh must keep the POSTERN_PACKAGING_E2E env gate on \
         its full (build) mode"
    );
    assert!(
        lower.contains("unaudited"),
        "package-signed.sh must keep its `unaudited` honesty marker"
    );
    assert!(
        lower.contains("reproducible where the platform allows"),
        "package-signed.sh must keep its `reproducible where the platform \
         allows` honesty marker (it must never claim bit-for-bit \
         reproducibility)"
    );
    assert!(
        script.contains("packaging/build-signed-bundle.sh"),
        "package-signed.sh must keep referencing (reusing) \
         packaging/build-signed-bundle.sh"
    );
    assert!(
        script.contains("scripts/sign-release.sh"),
        "package-signed.sh must keep referencing (reusing) \
         scripts/sign-release.sh"
    );
}

#[test]
fn gen_dev_signing_keys_scaffold_stays_placeholder_only() {
    // Regression tripwire over gen-dev-signing-keys.sh, NOT an audit: the
    // scaffold's whole safety story is that it only ever mints CLEARLY-MARKED
    // placeholder keys. That posture lives in a handful of literal strings —
    // strict shell mode, the `dev-sample` token that trips sign-release.sh's
    // guard, the DO-NOT-SHIP key directory, and the pledge not to touch the
    // reused pipelines. An edit that quietly drops any of them (e.g. renaming
    // the keys to something that looks production-grade) should fail here as a
    // reviewed change, not slip through.
    let script = read("gen-dev-signing-keys.sh");
    let lower = script.to_lowercase();

    assert!(
        script.contains("set -euo pipefail"),
        "gen-dev-signing-keys.sh must keep `set -euo pipefail`"
    );
    assert!(
        script.contains("dev-sample"),
        "gen-dev-signing-keys.sh must keep the `dev-sample` token — it is the \
         exact string that trips the DEV/SAMPLE guard in scripts/sign-release.sh"
    );
    assert!(
        script.contains("dev-keys-DO-NOT-SHIP"),
        "gen-dev-signing-keys.sh must keep writing into `dev-keys-DO-NOT-SHIP/`"
    );
    assert!(
        lower.contains("placeholder"),
        "gen-dev-signing-keys.sh must keep its `placeholder` honesty marker"
    );
    assert!(
        script.contains("Does NOT modify packaging/ or scripts/"),
        "gen-dev-signing-keys.sh must keep its pledge not to modify the reused \
         packaging/ and scripts/ pipelines"
    );
}

#[test]
fn dev_signing_keys_are_gitignored() {
    // The scaffold writes real (throwaway) key material by default into
    // desktop/src-tauri/dev-keys-DO-NOT-SHIP/. A local .gitignore must keep
    // that material — and any stray key files — out of the committed tree.
    let ignore = read(".gitignore");
    assert!(
        ignore.contains("dev-keys-DO-NOT-SHIP/"),
        ".gitignore must exclude dev-keys-DO-NOT-SHIP/ so generated key \
         material is never committed"
    );
    for pat in ["*.minisign.key", "*.falcon.sec", "*.mldsa.seed"] {
        assert!(
            ignore.contains(pat),
            ".gitignore must exclude `{pat}` so stray secret key material is \
             never committed"
        );
    }
}

#[test]
fn linux_deb_declares_runtime_dependencies() {
    let conf = read("tauri.conf.json");
    let bundle = json_object_body(&conf, "bundle");
    let linux = json_object_body(&bundle, "linux");
    let deb = json_object_body(&linux, "deb");

    let depends = json_string_array(&deb, "depends");
    assert!(
        !depends.is_empty(),
        "bundle.linux.deb.depends must not be empty — an empty depends list \
         would ship a .deb that silently omits its webkit2gtk/gtk3 runtime \
         requirements"
    );
}
