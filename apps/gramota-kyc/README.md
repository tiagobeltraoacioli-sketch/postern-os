<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Gramota — owner / manager identity KYC (on-device)

**Reference prototype · UNAUDITED · pre-production. Not legal advice.**
Proposed name, trademark pending.

Gramota is the **person → entity binder** for Postern Enterprise onboarding. It ties
the requesting **human** to the company that holds a **DUNS** number, so Company A
cannot register a corporate-master license against Company B's *public* DUNS. It
implements **Option E** of `Postern-Enterprise-Owner-KYC-Design.md`: **on-device OCR**
of the owner/manager authority + ID documents, **validated fail-closed** against the
Dun & Bradstreet entity, emitting only a **minimal, PII-free verdict**.

## The non-negotiable privacy rule

OCR and field validation run **entirely on the device** (in the browser). **Document
images, raw OCR text, names, and document numbers NEVER leave the device and NEVER
reach a Postern server.** Only a minimal verdict crosses the wire:

```jsonc
{ "ocr": { "onDevice": true, "match": true, "fieldsMatched": ["legalName","country"], "liveness": false } }
```

booleans, the **names of matched fields** (never their values), and an assurance
level. This is LGPD/GDPR data minimization by construction: the data is processed
*by the subject, on the subject's device*.

- A **server / third-party OCR** path, if ever offered for low-power devices, must be
  **explicitly labeled the less-private option, strictly opt-in** (separate consent),
  under a DPA — never the default. It is **not** implemented here.
- The server endpoint (`/license/review`) enforces this with a **PII/image tripwire**
  (`scanForPII`) that **refuses** any request carrying a document image, a `data:` URI,
  an over-long string, or a blocked key (name/dob/document-number/address/…).

## Honest limitation (stated plainly)

**A document read is NOT proof of authority.** OCR proves *text was extracted*, not
that a document is authentic, current, unrevoked, or that it genuinely grants
authority — and not that the presenter is its subject. "Authorized manager" is an
internal delegation that appears in **no public registry** and cannot be verified
absolutely. Every verdict keeps `self_declared: true` and `ocr.onDevice: true` so
nothing ever reads as identity- or authority-*proven* when it was only attested.
OCR is spoofable (a forged image OCRs fine); hence it sits at LoA-2 and only reaches
LoA-3 combined with liveness/authenticity, with full IDV as the escalation.

## Flow

1. **Resolve entity** — `POST /license/review {duns, resolve:true}` returns the D&B
   `legalName` + `country` (business/entity data only, already public in the issued
   token) so the browser can compare **on-device**.
2. **Read documents on-device** — authority doc (articles/POA/board resolution) + a
   government ID. Images are held as local blobs (`img-src blob:`) and discarded; they
   are never uploaded. The document **reader** is a pluggable, fail-closed seam
   (`<script id="grm-ocr">`, `makeOcrEngine`): a self-hosted **Tesseract WASM** engine
   (`window.Tesseract`) or any `read(file)`/`recognize(file)` adapter is used **if
   present**; no reader is bundled, so the honest default is **manual on-device entry**.
   The engine **never fabricates a read** — no file, an empty read, an unknown result
   shape, or an adapter that throws all fail-closed to manual (nothing is auto-filled),
   and a read alone **never lifts LoA** (a document read is not proof of authority).
   Pinned by `ocr-engine.test.mjs`.
3. **Validate on-device** — `GRM.validateOcrAgainstEntity` normalizes and compares
   (legal-suffix/diacritic/case-insensitive name match, ISO country match, optional
   officer/principal match). **Any field that cannot be confidently matched earns no
   LoA credit** (fail-closed).
4. **Submit the minimal verdict** — `POST /license/review {duns, role, attestation,
   kyc:{ocr:{…}}}`. The server re-verifies the DUNS at D&B (fail-closed on `not-found`),
   computes the **authoritative** LoA, stores it under `kyc:<ref>` (≈1h TTL), and
   returns `{ ref, decision, loa, methods }`.
5. **Bind by reference** — pass `{ kyc_ref: ref }` to `POST /license/master` (or
   `/license/renew`). The server binds the **stored** verdict into the signed token, so
   a client **cannot inflate its own LoA**.

## Level of Assurance (faithful to design §3)

| LoA | Evidence | Decision when `KYC_MODE=enforce` |
|----|----------|----------|
| 0 | Self-declared only (today's behavior) | **provisional** |
| 1 | + corporate-domain proof (Option B) | pass |
| 2 | LoA-1 + D&B principal match **or** on-device OCR validated | pass |
| 3 | On-device OCR + liveness, or full IDV pass | pass (top) |

Default (unconfigured) returns today's **self-declared parity** — no regression.
Enforcement (`env.KYC_MODE = "enforce"`) caps LoA-0 at *provisional*; offline verifiers
enforce a **policy minimum LoA** with no network call, since the verdict rides inside
the Ed25519-signed token.

## Files

- `index.html` — the on-device app. `<script id="grm-core">` is the DOM-free,
  fail-closed validator (mirrors the authoritative server copy in
  `functions/license/review.js`); the UI layer never puts an image or OCR text in a
  network request.
- `test-core.mjs` — headless tests of the validators (`node test-core.mjs`).
- `review-seam.test.mjs` — tests of the `kycGate` seam + PII tripwire.
- `issuance.test.mjs` — proves the additive `kyc` token field is canonical-safe.

Run all: `node test-core.mjs && node review-seam.test.mjs && node issuance.test.mjs`

## Token field added (coordinate with the token schema)

A single **additive, canonical-safe** sibling object `kyc` is bound into the
vendor-signed token by `master.js` / `renew.js` (old tokens lack the key and still
verify). It is **PII-free** — booleans, method strings, matched field **names**, an
opaque `idvRef`, and the corporate `domain` (business data), never document values:

```jsonc
"kyc": {
  "loa": 2,                                  // enforceable 0..3
  "methods": ["self-declared","dnb-entity","corp-domain","ocr-ondevice"],
  "self_declared": true,                     // the claim is still a claim
  "ocr": { "onDevice": true, "match": true, "fieldsMatched": ["legalName","country"], "liveness": false },
  "principalMatch": false,                   // optional
  "domain": "acme.example", "domainProofAt": 0,  // optional (Option B)
  "idvRef": null,                            // optional opaque IDV reference (Option C)
  "verifiedAt": 0
}
```

The pre-existing `dnb` field (entity-side verdict) is unchanged; `kyc` is the
independent **person-side** verdict. Fiat is never the coin; any future billing is
fiat only and attaches at renewal.
