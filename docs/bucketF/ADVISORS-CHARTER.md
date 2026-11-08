<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Bucket F — ADVISORS CHARTER (3 adversarial reviewers)

Each advisor reviews **all 5 dev branches** after their HOST tests are reported
green, BEFORE the PMO integrates. Advisors do not write product code. Every
finding gets a **trust-label**: `critical` / `major` / `minor` / `nit`. **Gate:
`critical` count must be 0 before integration.** A finding that only asks for
polish is `nit`, not `major` — don't inflate.

Ground truth for all three advisors: `docs/bucketF/PARTITION.md` (what was
supposed to change and why) + a `git diff` against `roadmap/fleet2-integrate`
scoped to exactly that dev's owned files. Flag immediately, as `critical`, if a
dev touched a file outside their PARTITION.md ownership list — that's a
cross-dev collision risk the PMO needs to know about before merging.

---

## Advisor F1 — Correctness

**Mandate:** does the code do what it claims, including the edges no happy-path
test hits, and does it fail closed?

Per-dev correctness checklist:

- **F1 (daemon core):** Does `Daemon::tick` actually call `Orchestrator::reconcile`
  before servicing crossings (order matters — a stale persona state must not
  authorize a crossing against it)? Does the kill-switch check run BEFORE
  crossing delivery on every tick, not just at daemon startup? Does `--once`
  vs `--watch` share the identical tick logic (no fork in behavior between the
  tested path and the "real" path)? Is the bounded-iteration `--watch` loop
  actually bounded in the test (no accidental infinite loop hazard)?
- **F2 (persistence):** Does the `schema_version` check actually refuse an
  unknown version, or just log and continue (that would be silent, not
  fail-closed)? Does the fault-injection test really simulate a torn write
  (partial bytes on disk), not just "file doesn't exist yet"? Does the E2E
  HostStub test assert the **sealed-wallet invariant** survives the kill-switch
  (`sealedWallet.preserved == true`), matching the exact wording B10's design
  uses — a test that never checks this proves nothing about the invariant that
  matters most.
- **F3 (SDK wiring):** Does `postern-enterprise`/`tolmach-subscription`/
  `desktop vault.js` use the SAME `KDF_REAL` tag string (`"Argon2id-postern-sdk"`)
  as the other 6 apps — a typo'd tag silently breaks cross-app blob portability
  claims. Does the new wiring **read back** an already-PBKDF2-sealed blob
  correctly (no forced re-seal, no data loss) when `PosternSDK` becomes
  available later? Do the new test files actually install a **stub**
  `globalThis.PosternSDK` with the right method names (`deriveArgon2id`,
  `aeadSeal`, `aeadOpen`) rather than a shape that happens to pass because the
  test never calls through it?
- **F4 (TCB-info verify):** Does the signature verification actually chain to
  `PINNED_INTEL_SGX_ROOT_CA_DER` (the real pinned root), or to a test root that
  happens to make the offline vector pass without proving anything about the
  real trust chain (mirror the SNP root pin discipline this same crate already
  has for the PCK path)? Is a `tcbStatus` other than `UpToDate` actually
  enforced (rejected/degraded), or just parsed and ignored?
- **F5 (OCR engine, deploy files):** Does the new OCR adapter's `read()` still
  emit ONLY `{ engine, manual, text }` (the seam's own documented contract) —
  no accidental new field that widens what crosses off-device? Does the
  Dockerfile actually build (not just look plausible) — check it against the
  proven `enterprise/cloud/services/console/http/deploy/Dockerfile` pattern
  line by line for anything the comms app's dependency tree needs that the
  console's didn't (e.g., the wasm `seal-rs`/`verify-rs` sub-crates under
  `enterprise/comms/app/persistence` and `verification/`).

**Every "done" claim must cite a specific green test.** A correctness finding
with no reproduction (exact command + expected vs actual) is not actionable —
send it back for a repro before it counts.

---

## Advisor F2 — Security

**Mandate:** crypto misuse, replay/downgrade, and specifically: **is the SDK
parity wiring (F3) actually invoking the real Argon2id/XChaCha20 core, not
building a second stand-in that merely LOOKS wired?** Is F4's collateral
verification sound? Is F5's OCR seam still privacy-preserving (on-device only)?

- **F1/F2 (daemon + persistence):** Can the daemon be tricked into servicing a
  crossing whose `Direction` doesn't match the actual sender/receiver roles
  (the exact attack `consent_record.rs`'s pinned-direction design exists to
  stop — F1/F2 must not accidentally bypass that binding by, e.g., constructing
  a `CrossingRequest` from daemon-trusted fields instead of the verified
  `ConsentRecord`)? Does the kill-switch path in the daemon actually **drop the
  span** (deny everything) rather than merely pausing new crossings while an
  in-flight one still completes? Does persistence ever write an unsealed
  secret to disk in plaintext (grep the new `substrate.rs` diff for anything
  that isn't already covered by the existing zeroize/`write_atomic` discipline)?
- **F3 — the load-bearing check:** For EACH of the 3 newly-wired apps, confirm
  the "real" path calls `postern_core::kdf` (Argon2id, m=65536, t=3, p=1) +
  `postern_core::aead` (XChaCha20-Poly1305) via the ACTUAL `crates/postern-sdk`
  wasm build — not a second hand-rolled JS KDF that merely claims the label.
  Trace it: `globalThis.PosternSDK.deriveArgon2id(...)` must resolve to
  `crates/postern-sdk/src/wasm.rs`'s `VaultKey::derive`, which calls
  `postern_vault::derive_key`. If a dev wrote their own `argon2` JS shim
  instead of wiring the real wasm seam, that is a **critical** finding — it is
  exactly the failure mode Bucket F's own charter (from the PMO brief) singled
  out: "the SDK parity is actually the real core not another stand-in." Also
  confirm the new test files' stub `PosternSDK` in the "absent" test case does
  NOT accidentally leak into the "real" test case (shared global state across
  Node test file `assert` blocks is a classic false-green).
- **F4:** Is the signature-chain verification actually **fail-closed** on a
  malformed/missing TCB-info document (matches the crate's existing PCK-CRL
  discipline: "REJECTED unless explicitly bypassed"), or does an absent
  collateral document silently degrade to "not checked, assume OK"? Is the
  Intel TCB signing certificate itself validated against the pinned root chain
  (not just parsed and trusted)?
- **F5:** Does the OCR engine wiring preserve the non-negotiable privacy rule
  stated in `apps/gramota-kyc/README.md` — document images and raw OCR text
  **never leave the device**? If the chosen OCR library (e.g. Tesseract-wasm)
  needs to fetch a language-model file at runtime, does that fetch carry any
  request body containing document content (it must not — only the static
  model asset, ideally vendored, never the user's image)? Does the comms app
  Dockerfile/fly.toml avoid baking in any secret or credential (it should be
  build-only, secrets injected at `fly deploy` time — Bucket C, not F)?

**Nothing here removes the `unaudited` badge.** Every F-item stays labeled
UNAUDITED / reference-prototype regardless of how green its tests are — flag as
`critical` any doc/comment change that tries to upgrade that label.

---

## Advisor F3 — Honesty + test-integrity

**Mandate:** do the tests assert real behavior, not tautologies? No overclaim
in comments/docs/labels? `critical: 0` across all 5 devs? Nothing marked done
that isn't actually tested?

- **Tautology check (every new test file):** does the test call the function
  under test and assert on ITS output, or does it assert on a literal the test
  itself just constructed (a classic false-green — e.g. `assert.equal(x, x)`,
  or asserting a mock's return value equals the value the mock was configured
  to return, proving nothing about the real code path)?
- **Regression check:** did any dev's change cause a PREVIOUSLY green test
  elsewhere to silently start being skipped, or its assertion weakened, to make
  their own change pass? Diff the full test file, not just the new lines.
- **Label discipline:** every new/touched file must keep the existing honesty
  rails verbatim — "reference-prototype, UNAUDITED," "written ≠ built ≠
  booted ≠ attested ≠ deployed ≠ audited," "HOST-tested, not device-tested"
  where applicable. Flag any dev who softened a caveat to make their delta read
  more finished than it is (e.g., dropping "UNTESTED-until-device" from a
  substrate.rs comment because F1/F2 added a HOST test that does NOT actually
  exercise a device path).
- **Scope discipline:** does each dev's actual diff match PARTITION.md's file
  list exactly? A dev who quietly touched `consent_record.rs` or
  `bridge.rs` (owned by neither F1 nor F2 per this partition) to make their
  test pass is a `critical` finding — it's an undisclosed cross-cutting change
  to code three other devs and both other advisors assumed was frozen.
- **The F4 reassignment itself:** confirm F4's dev did NOT also touch
  `crates/postern-courier` — the PMO's correction explicitly found that item
  already shipped; any courier diff in this bucket is out-of-scope duplicate
  work and should be flagged (not necessarily harmful, but it means the dev
  didn't read PARTITION.md's stated reassignment rationale).
- **"Genuinely-unstarted" claims:** for F5's OCR item, confirm the PR doesn't
  claim "OCR now works" broadly — the honest claim is narrower: a specific
  adapter, tested against specific fixture images, still MANUAL by default
  when the adapter isn't installed. Check the updated `README.md`/comments
  reflect exactly that, not more.
- **critical:0 gate:** tally every advisor's critical-labeled findings across
  all 5 devs in a single list before signing off; if the count is not exactly
  zero, integration does not proceed for the affected dev(s).
