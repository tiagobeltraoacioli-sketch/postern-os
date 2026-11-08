#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
// Bloch (comms-app) — minimal static file server for the deployable image.
//
// WHAT THIS IS. Bloch (enterprise/comms/app/) is a self-contained, framework-free
// static app: index.html + ES modules, connect-src 'none' in its own CSP meta
// tag. It has no application server of its own — the app's own README says so
// ("Open index.html in a browser"). To deploy it as a container/Fly service
// (rather than a file:// open), *something* has to serve the static bytes over
// HTTP. This is that something: zero npm dependencies (matches the repo's
// existing test/tooling convention — see enterprise/comms/app/self-check.mjs),
// built only on Node's own `node:http` + `node:fs`.
//
// It serves the `enterprise/` subtree (not just `app/`) because the app's ES
// modules import across sibling directories with relative paths that escape
// `comms/app/` — e.g. `../../features/sub-access.mjs`,
// `../../features/license-hook.mjs`, `../../compliance/audit-trail.mjs`. The
// webroot must therefore be `enterprise/` itself so those relative imports
// resolve the same way over HTTP as they do on disk. Requests to `/` redirect
// to `/comms/app/index.html`.
//
// WHAT THIS IS NOT: not a production web server. No TLS termination (Fly's
// edge / the operator's LB owns that), no caching layer, no rate limiting, no
// compression. It reads a static file and writes it back, and answers
// `/healthz`. Static assets are the entire attack surface: it refuses any path
// that would leave the webroot (path-traversal guard below) and never executes
// or evaluates anything it serves.
"use strict";

import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = fileURLToPath(new URL(".", import.meta.url));
// deploy/ -> app/ -> comms/ -> enterprise/  (the webroot: see doc comment above)
const WEBROOT = normalize(join(HERE, "..", "..", ".."));
const PORT = Number.parseInt(process.env.PORT || "8080", 10);
const DEFAULT_DOC = "/comms/app/index.html";

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".mjs": "application/javascript; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".txt": "text/plain; charset=utf-8",
  ".map": "application/json; charset=utf-8",
};

// Decode a raw request URL's path component exactly once, stripping any
// query/hash first. Both the hidden-segment check and safeJoin() must reason
// about the SAME (decoded) string — decoding only inside safeJoin let a
// percent-encoded dot (e.g. `/features/%2egitignore`) sail past
// isHiddenSegment() (which saw the raw "%2egitignore" segment, not starting
// with ".") and then get decoded to ".gitignore" for the actual file read,
// serving a dotfile the guard was supposed to block. Decoding here first
// closes that gap; safeJoin() below takes the already-decoded path so the
// string is never decoded twice (which would mis-handle a literal "%25" in a
// filename).
function decodePath(urlPath) {
  const stripped = urlPath.split("?")[0].split("#")[0];
  try {
    return decodeURIComponent(stripped);
  } catch {
    // Malformed percent-encoding: fail closed rather than serve/guess.
    return null;
  }
}

// Never serve dotfiles, license/readme sources are fine but keep the surface
// to what the app actually needs: reject any path containing a segment that
// starts with "." (hidden files, .git, etc.) outright. MUST be called on the
// already-decoded path (see decodePath above), not the raw request URL.
function isHiddenSegment(decodedPath) {
  return decodedPath.split("/").some((seg) => seg.startsWith("."));
}

function safeJoin(root, decodedPath) {
  const normalized = normalize(decodedPath).replace(/^([.][.][/\\])+/, "");
  const full = normalize(join(root, normalized));
  // Path-traversal guard: resolved path must stay inside root.
  if (full !== root && !full.startsWith(root + sep)) return null;
  return full;
}

const server = createServer(async (req, res) => {
  try {
    const url = req.url || "/";

    if (url === "/healthz") {
      res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
      res.end("ok\n");
      return;
    }

    if (req.method !== "GET" && req.method !== "HEAD") {
      res.writeHead(405, { "content-type": "text/plain; charset=utf-8", allow: "GET, HEAD" });
      res.end("method not allowed\n");
      return;
    }

    const wantsPath = url === "/" ? DEFAULT_DOC : url;
    const decoded = decodePath(wantsPath);
    if (decoded === null) {
      res.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
      res.end("bad request\n");
      return;
    }
    if (isHiddenSegment(decoded)) {
      res.writeHead(403, { "content-type": "text/plain; charset=utf-8" });
      res.end("forbidden\n");
      return;
    }

    const filePath = safeJoin(WEBROOT, decoded);
    if (!filePath) {
      res.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
      res.end("bad request\n");
      return;
    }

    let st;
    try {
      st = await stat(filePath);
    } catch {
      res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      res.end("not found\n");
      return;
    }
    if (st.isDirectory()) {
      res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      res.end("not found\n");
      return;
    }

    const body = await readFile(filePath);
    const type = MIME[extname(filePath).toLowerCase()] || "application/octet-stream";
    res.writeHead(200, {
      "content-type": type,
      "content-length": body.length,
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "cache-control": "no-store",
    });
    res.end(req.method === "HEAD" ? undefined : body);
  } catch (err) {
    res.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
    res.end("internal error\n");
    console.error("[bloch-static-server]", err);
  }
});

// Only bind a port when run directly (`node server.mjs` / the deployed
// entrypoint) — not when imported (e.g. by the regression test below), so
// importing this module never opens a socket as a side effect.
if (fileURLToPath(import.meta.url) === process.argv[1]) {
  server.listen(PORT, () => {
    console.log(`[bloch-static-server] serving ${WEBROOT} on :${PORT} (default doc ${DEFAULT_DOC})`);
  });
}

// Exported for the regression test (server.dotfile-guard.test.mjs) — the pure
// path-safety helpers, not part of the deploy runtime's public contract.
export { decodePath, isHiddenSegment, safeJoin, WEBROOT };
