# mobile-attest test vectors — provenance

These are the FIRST non-synthetic Android Key-Attestation vectors in this crate.
Every other mobile-attest vector is `rcgen`-built in `mobile.rs`'s test module;
these were emitted by a real Android Keystore/KeyMint and captured off a booted
Android emulator, then committed verbatim.

## Capture receipt (this committed set)

Reproduced end-to-end by
[`tools/capture-android-attestation/capture-android-attestation.sh`](../../tools/capture-android-attestation/capture-android-attestation.sh)
on a booted emulator:

- Host: Intel x86_64 macOS (Hypervisor.framework acceleration).
- SDK: API-34, system image `system-images;android-34;google_apis;x86_64`,
  AVD `postern-capture`, headless (`-no-window -gpu swiftshader_indirect`).
- Key: EC P-256 generated in `AndroidKeyStore` via `KeyGenParameterSpec` with
  `setIsStrongBoxBacked(false)` (the **software / TEE-fallback** path — the
  `google_apis` emulator has no discrete StrongBox HSM) and
  `setAttestationChallenge(nonce)`. This is exactly the path
  `labs.postern.wallet.StrongBoxKey.generateTeeFallbackKey` drives on hardware;
  the capture harness is a stripped, `android.jar`-only APK that calls the
  identical Keystore APIs.

SHA-256 of the committed bytes:

```
038365858580e24b9c67ef804508537e7704f1f22ccddf4692347488abb3e2ac  chain-0.der
b98b2d687c24434b0ffa20eb889e180fe2d514883d695484ebb4ff83a6639b9b  chain-1.der
51d496ad4664190fbdaf1ad987278efa35d6fbf52e50a9c34ded8395477ede5c  chain-2.der
4300a04672376e8fe5a75a1bde683ea1de5d9a39e9d34ce4e8d5ca1ca175c035  nonce.bin
```

## `chain-0.der`, `chain-1.der`, `chain-2.der` — the captured chain (leaf-first)

A **real** Android Key-Attestation X.509 chain, leaf-first (index 0 = the
attested key's leaf), captured from a booted emulator — not hand-built, not
rcgen. Flowed byte-for-byte through `verify_key_attestation_detailed`.

- `chain-0.der` leaf (760 B, serial 01) — `CN=Android Keystore Key`, carries the
  Key-Attestation extension (OID `1.3.6.1.4.1.11129.2.1.17`) with our nonce, at
  `attestationSecurityLevel = Software(0)`. `teeEnforced` is empty; RootOfTrust
  lives only in `softwareEnforced`. Validity 1970-01-01 .. 2048-01-01.
- `chain-1.der` inter (636 B, serial 1001) —
  `O=Google, Inc., CN=Android Keystore Software Attestation Intermediate`.
  Validity 2016-01-11 .. **2026-01-08** (a fixed, long-lived AOSP software
  attestation intermediate, not a per-boot ephemeral).
- `chain-2.der` root (655 B, serial A2059ED10E435B57) —
  `O=Google, Inc., CN=Android Keystore Software Attestation Root` (self-signed).
  Validity 2016-01-11 .. 2036-01-06. This is the AOSP **software** attestation
  root, NOT a Google *production* hardware-attestation root — so the honest
  verdict is Genuine-*shape* at Software-tier *against this software root*, and a
  clean `Mismatch("trust anchor")` against a pinned Google *production* root
  (see below).

Because the intermediate's wall-clock validity ends 2026-01-08, the committed
test pins a fixed verifier clock (`CAPTURE_CLOCK_UNIX`, 2020-06-01 00:00:00 UTC)
inside every cert's window so the vector keeps verifying deterministically
regardless of the current date.

## `nonce.bin` — the attestation challenge (32 bytes)

The exact `setAttestationChallenge` input, `postern-seal-mobile-attest-nnc32`.
The verifier asserts the leaf's `attestationChallenge` equals these bytes
(freshness / anti-replay).

## `google_prod_attestation_root.der` — a real Google PRODUCTION root

The genuine Google hardware-attestation root certificate (self-signed,
serialNumber `f92009e853b6b045`; its RSA-4096 SubjectPublicKeyInfo equals the
`GOOGLE_ROOT_CA_PUB_KEY` published in Google's official
`google/android-key-attestation` sample). Pinned by the `..._mismatch...` test
to prove the emulator chain does **not** anchor to Google prod — an honest,
named `Verdict::Mismatch("trust anchor …")`, never a false Genuine. It is NOT
produced by the capture harness and the harness never touches it.

## `MANIFEST.txt`, `STATUS.txt` — capture-run receipts (bytes-per-cert, OK).

HONEST LIMIT: this is an EMULATOR-emitted chain rooted at the AOSP *software*
attestation CA. It proves the full parse+evaluate path runs against a real
Keystore-minted chain — it is NOT a StrongBox secure-element attestation and
carries no security claim. `captured ≠ StrongBox-hardware-attested`.

## Re-capture

`capture-android-attestation.sh capture --overwrite` regenerates an equivalent
real vector on demand. A fresh capture may mint an intermediate with a different
validity window; if so, re-pin `CAPTURE_CLOCK_UNIX` in `src/mobile.rs` inside the
new `chain-1.der` window (the harness prints each cert's window and a suggested
clock after a successful capture), then re-run
`cargo test -p postern-seal-companion --features mobile-attest captured_emulator_attestation`.
