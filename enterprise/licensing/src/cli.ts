#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// postern-license — vendor + org + local CLI for the Postern licensing library.
//
// Subcommands:
//   keygen-vendor [--out <file>]
//       (VENDOR) mint a fresh Ed25519 vendor keypair (raw base64).
//   issue    --vendor-priv <key|file> --tier <corporate-master|business-freemium>
//            [--duns <9-digit>] [--out <file>]
//       (VENDOR / site Function) issue a master token; also emits the org's
//       master keypair to return to the org.
//   mint-sub --master-priv <key|file> --master <masterToken.json>
//            --sub <label> [--exp <unix>] [--out <file>]
//       (ORG console) mint a sub token under a corporate master.
//   verify   --vendor-pub <key|file> --master <masterToken.json>
//            [--sub <subToken.json>]
//       (LOCAL) run the offline verification chain (crypto + structure + clock).
//   status   --vendor-pub <key|file> [--personal] [--master <f>] [--sub <f>]
//            [--now <iso>]
//       (LOCAL) resolve the entitlement state.
//   disclose --master <masterToken.json>
//       Print the up-front, honest first-run disclosure.
//
// Dependency-free (Node built-ins only). NEVER makes a network request.

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import {
  buildCrl,
  crlFreshness,
  describeState,
  disclosureForMaster,
  generateKeypair,
  issue,
  keyId,
  mintSubUnderMaster,
  status,
  verifyChain,
  verifyCrl,
  type Crl,
  type MasterToken,
  type SubToken,
} from "./index.js";

function parseArgs(argv: string[]): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a && a.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("--")) out[key] = true;
      else {
        out[key] = next;
        i++;
      }
    }
  }
  return out;
}

function die(msg: string): never {
  process.stderr.write(`error: ${msg}\n`);
  process.exit(1);
}

function str(v: string | boolean | undefined, name: string): string {
  if (typeof v !== "string" || v.length === 0) die(`missing --${name}`);
  return v;
}

/** Resolve a key argument: a raw base64 literal, or a path to a JSON/text file. */
function keyArg(v: string, fields: string[]): string {
  if (existsSync(v)) {
    const raw = readFileSync(v, "utf8").trim();
    try {
      const obj = JSON.parse(raw) as Record<string, unknown>;
      for (const f of fields) {
        if (typeof obj[f] === "string") return obj[f] as string;
      }
      die(`file ${v} has none of: ${fields.join(", ")}`);
    } catch {
      return raw; // plain base64 in a file
    }
  }
  return v; // literal base64
}

function readToken<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

/**
 * Read a master token from a file that is either a bare SignedToken
 * ({payload, sig}) or the wrapped output of `issue` ({masterToken, ...}).
 */
function readMaster(path: string): MasterToken {
  const obj = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  if (obj && typeof obj === "object" && "masterToken" in obj) {
    return obj.masterToken as MasterToken;
  }
  return obj as unknown as MasterToken;
}

const HELP = `postern-license — Postern licensing CLI (offline, no telemetry)

VENDOR (private key is a SERVER SECRET; the site Function reuses issue()):
  keygen-vendor [--out <file>]
  issue --vendor-priv <key|file> --tier <corporate-master|business-freemium>
        [--duns <9-digit>] [--out <file>]

ORG CONSOLE (holds the org master private key returned at issuance):
  mint-sub --master-priv <key|file> --master <masterToken.json>
           --sub <label> [--exp <unix>] [--out <file>]

REVOCATION / CRL (D4):
  crl-build  --vendor-priv <key|file> --version <n> [--vendor-pub <key|file>]
             [--iss <str>] [--kid <str>] [--jti <a,b,..>] [--master-pub <a,b,..>]
             [--next-update-secs <n>] [--max-stale-secs <n>] [--out <file>]
       (VENDOR) sign a versioned CRL over revoked serials / org master keys.
  crl-verify --vendor-pub <key|file> --crl <crl.json>
       (LOCAL) verify a CRL signature and report its soft-offline freshness.

LOCAL / SHIPPED APP (ships only the vendor PUBLIC key; fully offline):
  verify   --vendor-pub <key|file> --master <masterToken.json> [--sub <subToken.json>]
  status   --vendor-pub <key|file> [--personal] [--master <f>] [--sub <f>] [--now <iso>]
  disclose --master <masterToken.json>

Fiat, not any coin. No telemetry. Personal is free forever and needs no token.
`;

function cmdKeygenVendor(args: Record<string, string | boolean>): void {
  const kp = generateKeypair();
  const bundle = { vendorPrivateKey: kp.privateKey, vendorPublicKey: kp.publicKey };
  if (typeof args.out === "string") {
    writeFileSync(args.out, JSON.stringify(bundle, null, 2) + "\n");
    process.stderr.write(
      `wrote ${args.out}\nWARNING: contains the VENDOR PRIVATE key. Keep it in a secret manager; never commit it.\n`,
    );
  } else {
    process.stdout.write(JSON.stringify(bundle, null, 2) + "\n");
  }
}

function cmdIssue(args: Record<string, string | boolean>): void {
  const vendorPriv = keyArg(str(args["vendor-priv"], "vendor-priv"), [
    "vendorPrivateKey",
    "privateKey",
  ]);
  const tier = str(args.tier, "tier") as "corporate-master" | "business-freemium";
  const duns = typeof args.duns === "string" ? args.duns : null;
  const issued = issue(vendorPriv, { tier, duns });
  const out = {
    masterToken: issued.masterToken,
    orgMasterPrivateKey: issued.orgMasterPrivateKey,
    orgMasterPublicKey: issued.orgMasterPublicKey,
    _note:
      "Return orgMasterPrivateKey to the org over a secure channel so it can mint subs. Do NOT retain it server-side.",
  };
  if (typeof args.out === "string") {
    writeFileSync(args.out, JSON.stringify(out, null, 2) + "\n");
    process.stderr.write(`wrote ${args.out} (contains the org master PRIVATE key)\n`);
  } else {
    process.stdout.write(JSON.stringify(out, null, 2) + "\n");
  }
}

function cmdMintSub(args: Record<string, string | boolean>): void {
  const masterPriv = keyArg(str(args["master-priv"], "master-priv"), [
    "orgMasterPrivateKey",
    "privateKey",
  ]);
  const master = readMaster(str(args.master, "master"));
  const sub = str(args.sub, "sub");
  const exp = typeof args.exp === "string" ? Number(args.exp) : undefined;
  const token = mintSubUnderMaster(masterPriv, master, sub, exp);
  if (typeof args.out === "string") {
    writeFileSync(args.out, JSON.stringify(token, null, 2) + "\n");
    process.stderr.write(`wrote ${args.out}\n`);
  } else {
    process.stdout.write(JSON.stringify(token, null, 2) + "\n");
  }
}

function cmdVerify(args: Record<string, string | boolean>): void {
  const vendorPub = keyArg(str(args["vendor-pub"], "vendor-pub"), [
    "vendorPublicKey",
    "publicKey",
  ]);
  const master = readMaster(str(args.master, "master"));
  const sub = typeof args.sub === "string" ? readToken<SubToken>(args.sub) : null;
  const result = verifyChain(vendorPub, master, sub);
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  if (!result.ok) process.exit(2);
}

function cmdStatus(args: Record<string, string | boolean>): void {
  const vendorPub = keyArg(str(args["vendor-pub"], "vendor-pub"), [
    "vendorPublicKey",
    "publicKey",
  ]);
  const master = typeof args.master === "string" ? readMaster(args.master) : null;
  const sub = typeof args.sub === "string" ? readToken<SubToken>(args.sub) : null;
  const now = typeof args.now === "string" ? new Date(args.now) : new Date();
  const state = status({
    personal: args.personal === true,
    vendorPublicKey: vendorPub,
    master,
    sub,
    now,
  });
  process.stdout.write(describeState(state) + "\n");
  process.stdout.write(JSON.stringify(state, null, 2) + "\n");
}

function cmdDisclose(args: Record<string, string | boolean>): void {
  const master = readMaster(str(args.master, "master"));
  process.stdout.write(disclosureForMaster(master) + "\n");
}

/** (VENDOR) Build a signed, versioned CRL over revoked serials / master keys. */
function cmdCrlBuild(args: Record<string, string | boolean>): void {
  const vendorPriv = keyArg(str(args["vendor-priv"], "vendor-priv"), [
    "vendorPrivateKey",
    "privateKey",
  ]);
  const vendorPub = typeof args["vendor-pub"] === "string"
    ? keyArg(args["vendor-pub"], ["vendorPublicKey", "publicKey"])
    : null;
  const version = Number(str(args.version, "version"));
  if (!Number.isInteger(version) || version < 0) die("--version must be a non-negative integer");
  const splitList = (v: unknown): string[] =>
    typeof v === "string" && v.length > 0 ? v.split(",").map((x) => x.trim()).filter(Boolean) : [];
  const crl = buildCrl(vendorPriv, {
    iss: typeof args.iss === "string" ? args.iss : "posternlabs.com",
    kid: typeof args.kid === "string" ? args.kid : vendorPub ? keyId(vendorPub) : "unknown",
    version,
    revokedJti: splitList(args.jti),
    revokedMasterPub: splitList(args["master-pub"]),
    ...(typeof args["next-update-secs"] === "string" ? { nextUpdateSecs: Number(args["next-update-secs"]) } : {}),
    ...(typeof args["max-stale-secs"] === "string" ? { maxStaleSecs: Number(args["max-stale-secs"]) } : {}),
  });
  const outStr = JSON.stringify(crl, null, 2) + "\n";
  if (typeof args.out === "string") {
    writeFileSync(args.out, outStr);
    process.stderr.write(`wrote ${args.out} (signed CRL v${version})\n`);
  } else {
    process.stdout.write(outStr);
  }
}

/** (LOCAL) Verify a CRL signature + report its freshness. */
function cmdCrlVerify(args: Record<string, string | boolean>): void {
  const vendorPub = keyArg(str(args["vendor-pub"], "vendor-pub"), ["vendorPublicKey", "publicKey"]);
  const crl = readToken<Crl>(str(args.crl, "crl"));
  const res = verifyCrl(vendorPub, crl);
  const fresh = res.ok ? crlFreshness(crl) : null;
  process.stdout.write(JSON.stringify({ ...res, freshness: fresh }, null, 2) + "\n");
  if (!res.ok) process.exit(2);
}

function main(): void {
  const [, , cmd, ...rest] = process.argv;
  const args = parseArgs(rest);
  switch (cmd) {
    case "keygen-vendor":
      return cmdKeygenVendor(args);
    case "issue":
      return cmdIssue(args);
    case "mint-sub":
      return cmdMintSub(args);
    case "verify":
      return cmdVerify(args);
    case "status":
      return cmdStatus(args);
    case "disclose":
      return cmdDisclose(args);
    case "crl-build":
      return cmdCrlBuild(args);
    case "crl-verify":
      return cmdCrlVerify(args);
    case "help":
    case undefined:
    case "--help":
    case "-h":
      process.stdout.write(HELP);
      return;
    default:
      die(`unknown command "${cmd}" (try: help)`);
  }
}

main();
