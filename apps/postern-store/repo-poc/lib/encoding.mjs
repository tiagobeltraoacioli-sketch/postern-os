// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Direct, unmodified-logic port of enterprise/licensing/src/encoding.ts's
// canonicalJson(). A-repo-client.md §1.3 is explicit that index.json itself
// is NOT signed this way ("sign the file, don't canonicalize it" — the whole
// point is signer and verifier agree on exact served bytes without needing to
// agree on a canonicalization algorithm). canonicalJson stays useful in this
// POC only for the §4.2 CRL-shaped case (revocations.json), which the doc
// explicitly says IS the canonical-JSON case reused from crl.ts. Kept here so
// the POC can demonstrate that distinction rather than blur it.

export function canonicalJson(value) {
  return JSON.stringify(sortDeep(value));
}

function sortDeep(value) {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value && typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      if (value[key] === undefined) continue;
      out[key] = sortDeep(value[key]);
    }
    return out;
  }
  return value;
}

export function utf8(s) {
  return new Uint8Array(Buffer.from(s, "utf8"));
}
