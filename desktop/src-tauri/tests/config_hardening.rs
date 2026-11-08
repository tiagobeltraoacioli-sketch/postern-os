//! CI-style regression guards for the desktop app's two hardening surfaces:
//!
//!   1. `capabilities/default.json` — the Tauri v2 IPC capability allowlist —
//!      must stay **default-deny**: it may grant only the exact core:event
//!      permissions the vanilla UI uses. Any newly added permission fails this
//!      test until a human deliberately widens the allowlist below, so a silent
//!      grant (fs/shell/http/process, `core:default`, …) can't slip in.
//!
//!   2. `tauri.conf.json` — the window Content-Security-Policy — must stay
//!      strict: default-deny base, no `unsafe-eval`, no relaxed `script-src`,
//!      the anti-clickjacking / anti-injection directives locked to `'none'`,
//!      and `connect-src` confined to `'self'` + Tauri's IPC transport.
//!
//! These are dependency-free (std only) so they add no crate/`Cargo.lock`
//! churn. They are a *regression tripwire*, not a security audit: they assert
//! the config has not been weakened from its reviewed baseline. Nothing here
//! makes the app "secure" — CSP and a capability allowlist are defense-in-depth
//! on an unaudited, zero-security testnet build.

use std::collections::BTreeSet;
use std::path::PathBuf;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    let p = manifest_dir().join(rel);
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

// ── tiny, quote-literal JSON extractors (the two config files contain no
// escaped quotes inside the values we read, so this stays honest and simple) ──

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

/// Parse a CSP string into (directive → set-of-sources).
fn parse_csp(csp: &str) -> Vec<(String, BTreeSet<String>)> {
    csp.split(';')
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .map(|d| {
            let mut it = d.split_whitespace();
            let name = it.next().unwrap().to_string();
            let srcs: BTreeSet<String> = it.map(|s| s.to_string()).collect();
            (name, srcs)
        })
        .collect()
}

fn directive<'a>(
    csp: &'a [(String, BTreeSet<String>)],
    name: &str,
) -> &'a BTreeSet<String> {
    csp.iter()
        .find(|(n, _)| n == name)
        .map(|(_, s)| s)
        .unwrap_or_else(|| panic!("CSP is missing required directive `{name}`"))
}

fn only(sources: &BTreeSet<String>, expected: &[&str]) -> bool {
    let want: BTreeSet<String> = expected.iter().map(|s| s.to_string()).collect();
    *sources == want
}

// ──────────────────────────── capability allowlist ─────────────────────────

#[test]
fn capabilities_stay_default_deny() {
    let src = read("capabilities/default.json");

    // The ONLY permissions this window is allowed to grant. Widening the app's
    // IPC surface must be a deliberate, reviewed edit to THIS list — otherwise
    // this test fails, which is the point.
    const ALLOWED: &[&str] = &["core:event:allow-listen", "core:event:allow-unlisten"];
    let allowed: BTreeSet<&str> = ALLOWED.iter().copied().collect();

    let perms = json_string_array(&src, "permissions");
    assert!(!perms.is_empty(), "capability grants no permissions — unexpected");

    for p in &perms {
        assert!(
            allowed.contains(p.as_str()),
            "capabilities/default.json grants `{p}`, which is not in the reviewed \
             default-deny allowlist {ALLOWED:?}. If this widening is intended, add it \
             to ALLOWED in this test with justification; otherwise it is a regression."
        );
    }

    // Both baseline grants must remain present (no silent removal either).
    for want in ALLOWED {
        assert!(perms.iter().any(|p| p == want), "missing baseline permission `{want}`");
    }

    // The capability must stay window-local (not a global/remote capability).
    assert_eq!(
        json_string_value(&src, "identifier"),
        "default",
        "capability identifier changed unexpectedly"
    );
    assert!(
        src.contains("\"local\": true") || src.contains("\"local\":true"),
        "capability is no longer marked local:true"
    );
}

// ──────────────────────────────── window CSP ───────────────────────────────

#[test]
fn csp_stays_strict() {
    let conf = read("tauri.conf.json");
    let csp_str = json_string_value(&conf, "csp");
    let csp = parse_csp(&csp_str);

    // 1. Default-deny base: default-src is exactly 'self'.
    assert!(
        only(directive(&csp, "default-src"), &["'self'"]),
        "default-src must be exactly 'self' (default-deny base); got {:?}",
        directive(&csp, "default-src")
    );

    // 2. Scripts: 'self' only — never 'unsafe-inline'/'unsafe-eval' (XSS floor).
    assert!(
        only(directive(&csp, "script-src"), &["'self'"]),
        "script-src must be exactly 'self' — no unsafe-inline/unsafe-eval; got {:?}",
        directive(&csp, "script-src")
    );
    assert!(
        !csp_str.contains("'unsafe-eval'"),
        "CSP must not contain 'unsafe-eval' anywhere"
    );

    // 3. Anti-clickjacking / anti-injection sinks locked to 'none'.
    for dir in ["object-src", "base-uri", "frame-ancestors", "form-action"] {
        assert!(
            only(directive(&csp, dir), &["'none'"]),
            "{dir} must be exactly 'none'; got {:?}",
            directive(&csp, dir)
        );
    }

    // 4. connect-src confined to same-origin + Tauri's IPC transport only —
    //    no arbitrary http(s) origin and no wildcard exfil sink.
    let connect = directive(&csp, "connect-src");
    let permitted: BTreeSet<&str> =
        ["'self'", "ipc:", "http://ipc.localhost"].into_iter().collect();
    for s in connect {
        assert!(
            permitted.contains(s.as_str()),
            "connect-src has unexpected source `{s}` (allowed: 'self', ipc:, \
             http://ipc.localhost) — a broader network sink is a regression"
        );
    }

    // 5. No wildcard source may appear in ANY directive.
    for (name, srcs) in &csp {
        assert!(
            !srcs.contains("*"),
            "directive `{name}` contains a `*` wildcard source — regression"
        );
    }

    // 6. style-src may keep 'unsafe-inline' (the no-build UI needs inline
    //    styles) but must NOT gain 'unsafe-eval', and scripts stay unaffected.
    let style = directive(&csp, "style-src");
    assert!(
        !style.contains("'unsafe-eval'"),
        "style-src must not contain 'unsafe-eval'"
    );

    // 7. Unused fetch/embed sinks the README documents as least-privilege must
    //    stay pinned to exactly 'none' — dropping one back to inherit
    //    `default-src` would silently widen the surface.
    for dir in ["font-src", "media-src", "worker-src", "child-src", "frame-src", "manifest-src"] {
        assert!(
            only(directive(&csp, dir), &["'none'"]),
            "{dir} must be exactly 'none' (documented least-privilege sink); got {:?}",
            directive(&csp, dir)
        );
    }

    // 8. img-src is same-origin only — no `data:`/remote image sink.
    assert!(
        only(directive(&csp, "img-src"), &["'self'"]),
        "img-src must be exactly 'self'; got {:?}",
        directive(&csp, "img-src")
    );
}
