// SPDX-License-Identifier: MIT OR Apache-2.0
//
// signer-bridge.js — a THIN bridge from Node to `postern-mobile-signer`.
//
// The reference web UI cannot call Rust directly, so this module spawns the
// `signer-cli` binary (which holds a real `MobileSigner`) and speaks its
// line-delimited JSON protocol. It reimplements NO crypto: every consequential
// answer (WYSIWYS prompt, consequence tier, hybrid signature) comes back from
// the Rust engine.
//
// If the binary is not built, the bridge drops into an explicit, clearly-labelled
// PREVIEW mode: it drives the UI's state machine so the flow can be inspected,
// but it SIGNS NOTHING and fabricates no signature — it says so on every reply.
// This is the honest posture: the mobile OS image is UNBOOTED and this is a
// reference driver, not a shipped phone app.
"use strict";

const { spawn } = require("node:child_process");
const path = require("node:path");
const fs = require("node:fs");
const crypto = require("node:crypto");

// Candidate locations for the compiled engine driver.
const CLI_CANDIDATES = [
  path.join(__dirname, "..", "signer-cli", "target", "debug", "signer-cli"),
  path.join(__dirname, "..", "signer-cli", "target", "release", "signer-cli"),
];

function findCli() {
  for (const p of CLI_CANDIDATES) {
    try {
      if (fs.statSync(p).isFile()) return p;
    } catch (_) {
      /* not there */
    }
  }
  return null;
}

// ── Real path: talk to the Rust engine over stdio (request/response, in order) ──
class EngineBridge {
  constructor(cliPath) {
    this.mode = "engine";
    this.cliPath = cliPath;
    this.proc = spawn(cliPath, [], { stdio: ["pipe", "pipe", "inherit"] });
    this._buf = "";
    this._queue = []; // pending resolvers, FIFO — the CLI answers in order
    this._ready = new Promise((res) => (this._readyResolve = res));

    this.proc.stdout.on("data", (chunk) => this._onData(chunk));
    this.proc.on("exit", (code) => {
      const err = new Error(`signer-cli exited (code ${code})`);
      while (this._queue.length) this._queue.shift().reject(err);
    });
  }

  _onData(chunk) {
    this._buf += chunk.toString("utf8");
    let nl;
    while ((nl = this._buf.indexOf("\n")) >= 0) {
      const line = this._buf.slice(0, nl).trim();
      this._buf = this._buf.slice(nl + 1);
      if (!line) continue;
      let obj;
      try {
        obj = JSON.parse(line);
      } catch (_) {
        continue;
      }
      // The very first line is the engine's readiness banner.
      if (obj.ready && this._readyResolve) {
        this._readyResolve(obj);
        this._readyResolve = null;
        continue;
      }
      const waiter = this._queue.shift();
      if (waiter) waiter.resolve(obj);
    }
  }

  ready() {
    return this._ready;
  }

  send(obj) {
    return new Promise((resolve, reject) => {
      this._queue.push({ resolve, reject });
      this.proc.stdin.write(JSON.stringify(obj) + "\n");
    });
  }
}

// ── Preview path: honest stand-in when the engine is not built ──────────────────
// Mirrors the engine's tier/sentence rules so the UI is faithful, but signs
// nothing. Every reply carries mode:"preview" and a note; approvals return no
// signature. This is NOT a wallet — it is a UI harness with the engine absent.
class PreviewBridge {
  constructor() {
    this.mode = "preview";
    this.session = null;
    this.peer = "Tiago's ThinkPad";
    this.testnet = true;
    this.pending = null; // { tier, req_nonce_hex, ... }
  }

  ready() {
    return Promise.resolve({ ok: true, ready: true, engine: "PREVIEW (no signer-cli built)" });
  }

  _fragment(nonceHex) {
    const h = crypto.createHash("sha3-256");
    h.update(Buffer.from("postern:approval-fragment:v1"));
    h.update(this.session);
    h.update(Buffer.from(nonceHex, "hex"));
    return h.digest("hex").slice(0, 6);
  }

  _disclosure() {
    return (
      "Postern signs in software. Your phone protects the key at rest and attests " +
      "the app, but the signing key is handled in memory — this is NOT a hardware " +
      "wallet. A rooted/jailbroken or malware-infected phone can steal the key."
    );
  }

  async send(obj) {
    const note =
      "PREVIEW — the postern-mobile-signer engine is NOT built, so nothing is " +
      "signed and no key exists. Build signer-cli for the real WYSIWYS + signature.";
    switch (obj.cmd) {
      case "ping":
        return { ok: true, pong: true, mode: "preview" };
      case "init": {
        this.testnet = obj.testnet !== false;
        this.peer = obj.peer || this.peer;
        this.session = obj.session_hex
          ? Buffer.from(obj.session_hex, "hex")
          : Buffer.alloc(16, 7);
        return {
          ok: true,
          mode: "preview",
          address: "bloch1t…preview-no-engine",
          session_hex: this.session.toString("hex"),
          peer: this.peer,
          network: this.testnet ? "testnet" : "mainnet",
          note,
        };
      }
      case "request_login": {
        const nonce = crypto.randomBytes(32).toString("hex");
        this.pending = {
          kind: "login",
          tier: "SingleTap",
          req_nonce_hex: nonce,
          org: obj.org || "acme",
          user: obj.user || "alice",
        };
        return { ok: true, mode: "preview", frame_hex: "preview:" + nonce, kind: "login", note };
      }
      case "request_transfer": {
        const nonce = crypto.randomBytes(32).toString("hex");
        this.pending = {
          kind: "transfer",
          tier: "ExplicitReview",
          req_nonce_hex: nonce,
          to_address: obj.to_address || "bloch1t…preview",
          amount: obj.amount ?? 1000,
          fee: obj.fee ?? 10,
        };
        return { ok: true, mode: "preview", frame_hex: "preview:" + nonce, kind: "transfer", note };
      }
      case "receive_frame": {
        const p = this.pending;
        if (!p) return { ok: false, error: "no request pending (preview)" };
        const sentence =
          p.kind === "login"
            ? `This signs a login challenge for "${p.user}" at "${p.org}". It proves you hold the wallet key — it can't move funds.`
            : `This moves ${p.amount} coins to ${p.to_address} (fee ${p.fee}, ${
                this.testnet ? "testnet" : "mainnet"
              }). A signature spends irreversibly — this cannot be undone.`;
        return {
          ok: true,
          mode: "preview",
          prompt: {
            tier: p.tier,
            sentence,
            can_move_funds: p.kind === "transfer",
            peer_device: this.peer,
            confirmation_fragment: this._fragment(p.req_nonce_hex),
            req_nonce_hex: p.req_nonce_hex,
            disclosure: this._disclosure(),
          },
          note,
        };
      }
      case "approve":
      case "approve_single_tap": {
        if (!this.pending) return { ok: false, error: "no request pending (preview)" };
        this.pending = null;
        return {
          ok: true,
          mode: "preview",
          matched: false,
          preview: true,
          signature_hex: null,
          public_key_hex: null,
          note:
            "PREVIEW approval — NOTHING WAS SIGNED. No key, no signature. The real " +
            "engine returns a hybrid Falcon‖ML-DSA signature here.",
        };
      }
      case "decline":
        this.pending = null;
        return { ok: true, mode: "preview", declined: true, note };
      case "set_login_grant":
        return { ok: true, mode: "preview", grant_expires_at_unix: obj.expires_at_unix || 0, note };
      case "revoke_grant":
        return { ok: true, mode: "preview", revoked: true, note };
      case "address":
        return { ok: true, mode: "preview", address: "bloch1t…preview-no-engine" };
      default:
        return { ok: false, error: `unknown cmd (preview): ${obj.cmd}` };
    }
  }
}

// Pick the engine if built, else the honest preview.
function createBridge() {
  const cli = findCli();
  if (cli) return new EngineBridge(cli);
  return new PreviewBridge();
}

module.exports = { createBridge, findCli };
