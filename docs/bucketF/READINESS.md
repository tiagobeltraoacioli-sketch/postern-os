<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Bucket F — READINESS (per-item: buildable-here / needs-design-first / actually-gated)

Legend:
- **buildable-and-testable-here** — a Bucket-F dev can write real code today and
  prove it green with `cargo test`/`node`/`docker build`, no external input.
- **needs-design-first** — the HOST-testable core is buildable, but one design
  decision should be made explicit before/during the work (noted per item).
- **actually-gated** — despite being in this bucket, on inspection it has a real
  external dependency and should be flagged to the operator rather than
  silently attempted.

| Item | Dev | Status | Notes |
|---|---|---|---|
| NoporIS daemon/state-machine core | F1 | **buildable-and-testable-here** | Composes existing, already-host-tested library pieces (`Orchestrator`, `Substrate`, `HostStub*`). No new crypto, no new consent logic — pure composition + a CLI entrypoint. Lowest-risk item in the bucket. |
| NoporIS persistence hardening + full-loop E2E | F2 | **buildable-and-testable-here** | Schema versioning and fault-injection tests are standard Rust; the HostStub-only E2E loop needs no device. |
| SDK Argon2id/XChaCha20 wiring (3 apps) + parity tests (9 apps) | F3 | **buildable-and-testable-here** | The wasm core and the wiring *pattern* both already exist and are proven in 6 sibling apps — this is mechanical replication, not novel design. |
| Intel TCB-info/QE-identity collateral verification | F4 | **needs-design-first** | Buildable and host-testable with offline vectors (mirrors the existing PCK-CRL pattern in the same crate). The one open design call: whether a **missing** TCB-info document (vs. a present-but-invalid one) should be treated identically fail-closed, or degrade to the current CRL-`nextUpdate`-only freshness check as an explicit, documented fallback tier. Either answer is fine — just needs to be a stated decision, not an implicit one, since it changes what "closes it" means. Advisor F2 should confirm whichever choice was made is actually fail-closed in the harder direction. |
| wasm-bindgen glue emission (`postern_sdk.js`/`postern_sdk_bg.wasm`) | F5a | **needs-design-first** (tooling availability) | The `cargo build --target wasm32-unknown-unknown` compile gate is unconditionally host-testable and IS the real proof of "the seam builds." The glue-EMISSION step additionally needs `wasm-bindgen-cli` **version-matched** to the `wasm-bindgen` crate pinned in `Cargo.lock` — if that tool isn't installable in the dev's sandbox, `build-wasm.sh` already handles this honestly (prints instructions, exits 0, does not fake the artifact). Treat "compile gate green" as the F5 pass criterion; glue emission is a bonus, not a blocker. Do not let this item's tooling uncertainty block F5's other two deliverables. |
| Gramota on-device OCR engine (real recognizer behind the `grm-ocr` seam) | F5b | **needs-design-first** | The seam contract, honesty tests, and MANUAL-by-default fallback all already exist and are well-tested — genuinely just needs a real recognizer wired in. Design call before coding: which library (Tesseract-wasm vs. an ONNX/Transformers.js text model) and whether its model-weight asset is vendored into the repo (as other wasm crates already do, e.g. `crates/ezekiel1/wasm`) vs. fetched at first-run. Vendoring keeps the HOST test fully offline and reproducible — recommended, and consistent with repo convention — but is a repo-hygiene call (binary asset size) that should be made explicitly rather than defaulted. Not a hard external gate: no account, no hardware, no credential needed either way. |
| Comms app deploy wiring (Dockerfile/fly.toml, build-only) | F5c | **buildable-and-testable-here** | Direct precedent exists (`enterprise/cloud/services/console/http/deploy/`); `docker build` proves it locally with zero secrets. Actually deploying it (`fly deploy`) is out of scope — that's Bucket C, correctly excluded here. |
| ~~Courier sender-auth/anti-replay~~ | ~~F4 (original)~~ | **already done — removed from Bucket F** | Verified in-tree: `crates/postern-courier` has had this ON BY DEFAULT since before fleet2 (commit `c25813c`), with 8 passing tests covering forgery, replay, staleness, and wire round-trip. The PMO brief's premise here was stale; F4 was reassigned (see PARTITION.md corrections) rather than have a dev re-implement finished work. Flagging this explicitly per the READINESS charter's instruction to "move it out of F honestly" when an item turns out not to need doing. |

## Summary

**5 of 5 assigned dev-buckets are genuinely buildable-and-testable-here** —
that was the point of Bucket F, and it holds. Two items (F4, F5b) carry a
**design decision**, not an external blocker, and both decisions are cheap
(pick a fallback-tier policy; pick a vendoring convention) — neither should be
allowed to stall the coding. One item (F5a, glue emission) has a soft
tooling dependency that the codebase already handles honestly by degrading
rather than blocking, so it doesn't gate F5's pass/fail either.

**Nothing in this bucket is actually resource-gated** (no box, no TEE
hardware, no operator secret, no external contract) — the one item that
*looked* like it might need re-scoping (courier) turned out to already be
closed, not gated; it was removed from the bucket entirely rather than
mis-filed as "gated." That is the correct outcome per the READINESS mandate:
be honest when an item doesn't belong in F, in either direction.
