// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Postern CLOUD — Consiglio wallet-login VERIFIER BRIDGE (reference prototype).
//
// STATUS: design / reference prototype. UNAUDITED. Pre-production.
//
// WHAT THIS IS
// ------------
// The JavaScript side of "wire the real Rust verifier behind the JS bridge".
// The console cannot run the hybrid Falcon-1024 ‖ ML-DSA-65 verifier in JS, so
// the reference console injected a STRING STUB — `walletSigner.sign` returned
// `"SIG(" + token + ")"` and the "verify" just checked the string shape. That is
// NOT cryptography. This bridge replaces it: it spawns the REAL
// `consiglio-verify` binary (crates/postern-consiglio-auth, feature
// `verifier-bin`), which reconstructs the exact domain-separated login
// transcript and verifies the signature with `bloch_crypto::crypto::verify` —
// the same hybrid-PQ verifier the node runs.
//
// FAIL-CLOSED, ALWAYS
// -------------------
//  - If the verifier binary is not built, `available()` is false and `verify()`
//    THROWS. It NEVER returns a positive verdict without the real check — there
//    is no silent downgrade to a stub. (Mirrors the seal engine's fail-closed
//    wasm → CLI → throw rule.)
//  - A non-zero exit, unparseable output, or `ok:false` is a rejection.
//
// The bridge holds NO keys and NO state: it answers exactly one question per
// call — "does this hybrid-PQ signature verify over this login transcript?".
//
// ORIGIN/KEY HARDENING (managed-node control plane)
// -------------------------------------------------
// The verifier binary IS the cryptographic trust anchor of wallet-as-login, so
// WHERE it comes from matters. By default this bridge auto-discovers the binary
// by scanning the workspace `target/` (release, then debug). On a shared build
// host that is a provenance risk: anything dropped at `target/debug/consiglio-
// verify` would be spawned. So an operator can PIN the trusted binary with the
// `CONSIGLIO_VERIFIER_BIN` env var — and when it is set, the pin is enforced
// FAIL-CLOSED: the bridge uses exactly that path and REFUSES to silently fall
// back to a target/-scan (a missing pinned binary throws at construction). The
// `target/` scan is used only when no pin and no explicit binPath is given.

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, isAbsolute, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Locate the compiled `consiglio-verify` binary. The crate is part of the Rust
 * workspace, so its binaries land in the workspace `target/` (release preferred
 * over debug); we also check a crate-local target as a fallback.
 * @returns {string|null} an existing path, or null if not built.
 */
export function defaultVerifierPath() {
  const repoRoot = join(__dirname, "..", "..", "..", "..");
  const candidates = [
    join(repoRoot, "target", "release", "consiglio-verify"),
    join(repoRoot, "target", "debug", "consiglio-verify"),
    join(repoRoot, "crates", "postern-consiglio-auth", "target", "release", "consiglio-verify"),
    join(repoRoot, "crates", "postern-consiglio-auth", "target", "debug", "consiglio-verify"),
  ];
  for (const p of candidates) if (existsSync(p)) return p;
  return null;
}

/** Human label for the real, PQ-backed verifier. */
export const REAL_VERIFIER_LABEL =
  "REAL Consiglio verifier (hybrid Falcon-1024 ‖ ML-DSA-65 via bloch_crypto) — spawned native binary";

/**
 * Resolve the verifier binary FAIL-CLOSED with a pin precedence:
 *   1. an explicit `opts.binPath` (tests / embedders) — used as given;
 *   2. `CONSIGLIO_VERIFIER_BIN` env pin — ENFORCED: it must be an absolute path
 *      that exists, or construction throws (no silent fallback to a scan);
 *   3. otherwise the workspace `target/` auto-scan (may be null if unbuilt).
 * @param {string} [explicit] opts.binPath
 * @param {object} [env] environment (default process.env)
 * @returns {string|null}
 */
export function resolveVerifierPath(explicit, env = process.env) {
  if (explicit) return explicit;
  const pinned = (env.CONSIGLIO_VERIFIER_BIN || "").trim();
  if (pinned) {
    if (!isAbsolute(pinned)) {
      throw new Error(
        "consiglio-verifier: CONSIGLIO_VERIFIER_BIN must be an ABSOLUTE path to the " +
          "trusted verifier binary (fail-closed: refusing a relative/ambiguous pin).",
      );
    }
    if (!existsSync(pinned)) {
      throw new Error(
        `consiglio-verifier: the pinned CONSIGLIO_VERIFIER_BIN does not exist: ${pinned}. ` +
          "Refusing to fall back to a target/ scan (fail-closed) — a pin means run EXACTLY that binary.",
      );
    }
    return pinned;
  }
  return defaultVerifierPath();
}

/**
 * Build the verifier bridge.
 * @param {object} [opts]
 * @param {string} [opts.binPath]  override the binary location. When unset, the
 *                                 `CONSIGLIO_VERIFIER_BIN` pin is honored
 *                                 fail-closed, else the workspace target/ scan.
 * @param {number} [opts.timeoutMs] per-verify timeout (default 5000).
 */
export function createConsiglioVerifier(opts = {}) {
  const binPath = resolveVerifierPath(opts.binPath);
  const timeoutMs = opts.timeoutMs || 5000;

  return {
    label: REAL_VERIFIER_LABEL,
    binPath,

    /** Is the real verifier binary present and usable? */
    available() {
      return typeof binPath === "string" && existsSync(binPath);
    },

    /**
     * Verify a login attempt with the REAL hybrid-PQ verifier. FAIL-CLOSED:
     * throws if the binary is missing (never a silent stub), rejects on any
     * error or `ok:false`.
     *
     * @param {object} req
     * @param {string} req.public_key_b64
     * @param {string} req.signature_b64
     * @param {string} req.org_id
     * @param {string} req.user_id
     * @param {string} req.nonce_hex   64 hex chars
     * @param {number} req.issued_at   unix seconds
     * @returns {Promise<{ok:boolean, reason?:string}>}
     */
    verify(req) {
      if (!this.available()) {
        return Promise.reject(
          new Error(
            "consiglio-verifier: the real verifier binary is not built. Build it with " +
              "`cargo build --release --features verifier-bin --bin consiglio-verify` in " +
              "crates/postern-consiglio-auth. This bridge NEVER falls back to a signature stub.",
          ),
        );
      }
      return new Promise((resolve, reject) => {
        const child = spawn(binPath, [], { stdio: ["pipe", "pipe", "pipe"] });
        let out = "";
        let err = "";
        let settled = false;
        const timer = setTimeout(() => {
          if (settled) return;
          settled = true;
          child.kill("SIGKILL");
          reject(new Error("consiglio-verifier: verify timed out"));
        }, timeoutMs);

        child.stdout.on("data", (d) => (out += d));
        child.stderr.on("data", (d) => (err += d));
        child.on("error", (e) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          reject(e);
        });
        child.on("close", (code) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          if (code !== 0) {
            // A crash is a rejection, not an acceptance (fail-closed).
            return resolve({ ok: false, reason: `verifier exited ${code}: ${err.trim()}` });
          }
          try {
            const parsed = JSON.parse(out.trim());
            resolve({ ok: parsed.ok === true, reason: parsed.reason });
          } catch {
            resolve({ ok: false, reason: "verifier produced unparseable output" });
          }
        });

        child.stdin.write(JSON.stringify(req));
        child.stdin.end();
      });
    },
  };
}

export default { createConsiglioVerifier, defaultVerifierPath, resolveVerifierPath, REAL_VERIFIER_LABEL };
