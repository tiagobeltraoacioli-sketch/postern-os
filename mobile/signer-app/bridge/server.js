// SPDX-License-Identifier: MIT OR Apache-2.0
//
// server.js — a tiny, dependency-free HTTP host for the reference signer UI.
//
// It serves the framework-free web UI from ../web and exposes ONE endpoint,
// POST /api, which forwards a JSON command to the signer bridge (the real Rust
// engine `signer-cli`, or the honest preview stand-in). It adds no logic of its
// own — it is glue so a browser can drive `postern-mobile-signer`.
//
// Local-only by default (binds 127.0.0.1). This is a REFERENCE DRIVER you run on
// a workstation; the mobile OS image is UNBOOTED. Not a shipped phone app.
"use strict";

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const { createBridge, findCli } = require("./signer-bridge.js");

const WEB_DIR = path.join(__dirname, "..", "web");
const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 8787);

const bridge = createBridge();

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

function serveStatic(req, res) {
  let rel = decodeURIComponent(req.url.split("?")[0]);
  if (rel === "/") rel = "/index.html";
  // Contain within WEB_DIR — no traversal.
  const full = path.normalize(path.join(WEB_DIR, rel));
  if (!full.startsWith(WEB_DIR)) {
    res.writeHead(403).end("forbidden");
    return;
  }
  fs.readFile(full, (err, buf) => {
    if (err) {
      res.writeHead(404, { "content-type": "text/plain" }).end("not found");
      return;
    }
    res.writeHead(200, { "content-type": MIME[path.extname(full)] || "application/octet-stream" });
    res.end(buf);
  });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => {
      data += c;
      if (data.length > 1_000_000) reject(new Error("body too large"));
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  if (req.method === "POST" && req.url === "/api") {
    try {
      const body = await readBody(req);
      const cmd = body ? JSON.parse(body) : {};
      const out = await bridge.send(cmd);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(out));
    } catch (e) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: String(e && e.message ? e.message : e) }));
    }
    return;
  }
  if (req.method === "GET" && req.url === "/mode") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ mode: bridge.mode, cli: findCli() }));
    return;
  }
  if (req.method === "GET") return serveStatic(req, res);
  res.writeHead(405).end("method not allowed");
});

bridge.ready().then((banner) => {
  server.listen(PORT, HOST, () => {
    const where = `http://${HOST}:${PORT}`;
    console.log(`\n  Postern reference signer driver`);
    console.log(`  mode: ${bridge.mode}${bridge.mode === "engine" ? " (real postern-mobile-signer)" : " (no signer-cli built — NOTHING is signed)"}`);
    console.log(`  engine banner: ${banner && banner.engine ? banner.engine : "n/a"}`);
    console.log(`  open: ${where}`);
    console.log(`\n  REFERENCE DRIVER — the mobile OS image is UNBOOTED; this is not a shipped phone app.`);
    console.log(`  Software keystore, not hardware. Per-sign presence. Unaudited scaffold. The coin is not a security.\n`);
  });
});
