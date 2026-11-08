// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// postern-shield-seal — the REAL seal adapter for the SHIELD work-container.
//
// STATUS: reference prototype — UNAUDITED, pre-production.
//
// WHAT THIS IS
// ------------
// The container (enterprise/shield/container/src/shield-container.mjs) seals its
// corporate data at rest through an INJECTED seal engine with three ops:
//
//     deriveKey(secretBytes, salt) -> key32   (Argon2id, per postern-vault)
//     seal(key32, plaintextBytes)  -> sealedBytes
//     open(key32, sealedBytes)     -> plaintextBytes   (throws on wrong key / tamper)
//
// This binary is the REAL implementation of that interface. It defines NO crypto
// of its own: every operation delegates to the ONE canonical Postern seal in
// `postern_core` — XChaCha20-Poly1305 (versioned, key-committing, context-bound)
// with the 32-byte key from Argon2id at the at-rest tier. The container's JS
// integration adapter (src/real-seal-engine.mjs) spawns this CLI once per op.
//
// HONEST LIMITS (unchanged by making the seal real)
// -------------------------------------------------
//  * The seal is real, but the CONTAINER around it is still containment BY
//    CONSTRUCTION (userland), NOT a kernel boundary: a rooted / jailbroken phone,
//    a debugger, or a RAM capture defeats it. Making the at-rest bytes genuinely
//    AEAD-sealed does not change that.
//  * Passing keys through a spawned process is a prototype wiring, not a
//    production key-handling design (a real deployment would use in-process
//    FFI/WASM so the key never crosses a process boundary). Labeled as such.
//  * The seal NEVER touches the personal side of the device; it only transforms
//    bytes the corporate container hands it.
//
// WIRE PROTOCOL (kept trivial so JS needs no serializer)
// ------------------------------------------------------
//   argv[1] = command; the operands are hex, one per line on STDIN:
//     derive-key : line1 = secretHex, line2 = saltHex   -> stdout: keyHex (64)
//     seal       : line1 = keyHex(64), line2 = ptHex     -> stdout: sealedHex
//     open       : line1 = keyHex(64), line2 = sealedHex -> stdout: ptHex
//   stdout is lowercase hex + trailing '\n'. Exit codes:
//     0 ok · 2 usage/parse · 3 open failed (wrong key / tamper / corrupt) · 4 kdf/other

use std::io::Read;
use std::process::ExitCode;

// Domain/context string binding blobs to the SHIELD container (see
// postern_core::aead::seal_with_context). A blob sealed here under a given
// 32-byte key can NOT be opened as a vault, a courier message, or any other
// Postern product, even under the same key — and vice versa.
const SHIELD_CONTEXT: &[u8] = b"postern-shield/container/v1";

fn main() -> ExitCode {
    let cmd = match std::env::args().nth(1) {
        Some(c) => c,
        None => return usage("missing command"),
    };

    let mut stdin = String::new();
    if std::io::stdin().read_to_string(&mut stdin).is_err() {
        return usage("could not read stdin");
    }
    let mut lines = stdin.lines();
    let line1 = lines.next().unwrap_or("").trim();
    let line2 = lines.next().unwrap_or("").trim();

    match cmd.as_str() {
        "derive-key" => {
            let secret = match from_hex(line1) {
                Some(b) => b,
                None => return usage("secret is not valid hex"),
            };
            let salt = match from_hex(line2) {
                Some(b) => b,
                None => return usage("salt is not valid hex"),
            };
            match postern_core::kdf::derive_key(&secret, &salt) {
                // The key derefs to [u8; 32]; print it and let the Zeroizing
                // wrapper wipe the source on drop.
                Ok(k) => emit(&k[..]),
                Err(e) => fail(4, &format!("kdf: {e}")),
            }
        }
        "seal" => {
            let key = match key32(line1) {
                Ok(k) => k,
                Err(c) => return c,
            };
            let pt = match from_hex(line2) {
                Some(b) => b,
                None => return usage("plaintext is not valid hex"),
            };
            match postern_core::aead::seal_with_context(&key, SHIELD_CONTEXT, &pt) {
                Ok(sealed) => emit(&sealed),
                Err(e) => fail(4, &format!("seal: {e}")),
            }
        }
        "open" => {
            let key = match key32(line1) {
                Ok(k) => k,
                Err(c) => return c,
            };
            let sealed = match from_hex(line2) {
                Some(b) => b,
                None => return usage("sealed blob is not valid hex"),
            };
            match postern_core::aead::open_with_context(&key, SHIELD_CONTEXT, &sealed) {
                Ok(pt) => emit(&pt),
                // Wrong key / tamper / corrupt: exit 3 so the JS adapter maps it
                // to a thrown open() — the "revoke => key gone => unreadable" path.
                Err(e) => fail(3, &format!("open: {e}")),
            }
        }
        "context" => emit_str(&String::from_utf8_lossy(SHIELD_CONTEXT)),
        other => usage(&format!("unknown command {other:?}")),
    }
}

fn key32(hexline: &str) -> Result<[u8; 32], ExitCode> {
    match from_hex(hexline) {
        Some(b) if b.len() == 32 => {
            let mut k = [0u8; 32];
            k.copy_from_slice(&b);
            Ok(k)
        }
        Some(_) => Err(usage("key must be exactly 32 bytes (64 hex chars)")),
        None => Err(usage("key is not valid hex")),
    }
}

fn emit(bytes: &[u8]) -> ExitCode {
    println!("{}", to_hex(bytes));
    ExitCode::SUCCESS
}

fn emit_str(s: &str) -> ExitCode {
    println!("{s}");
    ExitCode::SUCCESS
}

fn usage(msg: &str) -> ExitCode {
    eprintln!("postern-shield-seal: {msg}");
    eprintln!("usage: postern-shield-seal <derive-key|seal|open>  (operands: hex, one per line on stdin)");
    ExitCode::from(2)
}

fn fail(code: u8, msg: &str) -> ExitCode {
    eprintln!("postern-shield-seal: {msg}");
    ExitCode::from(code)
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
