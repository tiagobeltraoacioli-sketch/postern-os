# Reproducible Android Key-Attestation capture harness

Status: **reference harness, UNAUDITED.** Reproduces a *real* Keystore-minted
Android Key-Attestation chain from an emulator. **`captured != StrongBox-hardware-attested`** —
the `google_apis` emulator's KeyMint is a *software* reference implementation, so
the captured vector attests at `securityLevel = Software(0)` with **no**
hardware-enforced root of trust. This harness makes the existing
`captured_emulator_attestation` test vectors **reproducible**, not a one-off; it
carries no hardware security claim.

## What this is

The Rust test module `mobile::captured_emulator_attestation` in
[`src/mobile.rs`](src/mobile.rs) runs the full Android Key-Attestation
parse+evaluate pipeline over a **real** (non-synthetic) certificate chain that
was captured off a booted Android emulator and committed under
[`src/testdata/`](src/testdata/):

| file | role |
|------|------|
| `testdata/chain-0.der` | leaf — carries the Key-Attestation extension (OID `1.3.6.1.4.1.11129.2.1.17`) |
| `testdata/chain-1.der` | attestation intermediate (`O=Google, Inc., CN=Android Keystore Software Attestation Intermediate`) |
| `testdata/chain-2.der` | attestation root (`O=Google, Inc., CN=Android Keystore Software Attestation Root`, self-signed) |
| `testdata/nonce.bin`   | the 32-byte attestation challenge (`postern-seal-mobile-attest-nnc32`) |

Before this harness those bytes were a manual, undocumented one-off. This
directory is the **re-runnable** procedure that regenerates an equivalent real
vector on demand:

```
tools/capture-android-attestation/
├── capture-android-attestation.sh     # the driver (this doc's subject)
└── app/
    ├── AndroidManifest.xml             # minimal, no-resource, single activity
    └── src/labs/postern/capture/CaptureActivity.java
```

`CaptureActivity` is the "stripped, zero-dependency `android.jar`-only APK that
calls the identical Keystore APIs" referenced by
[`src/testdata/PROVENANCE.md`](src/testdata/PROVENANCE.md). It generates an
EC P-256 key inside `AndroidKeyStore` with `setAttestationChallenge(nonce)` and
`setIsStrongBoxBacked(false)` — the exact TEE / software-fallback path that
`labs.postern.wallet.StrongBoxKey.generateTeeFallbackKey` drives on hardware —
then emits the leaf-first DER chain the Keystore returns.

## Honesty contract

* The harness **never fabricates** a vector. Every DER byte it writes comes from
  a live emulator run; if the SDK/emulator is absent it fails loud and writes
  nothing.
* It writes into a **staging dir first** and only promotes to the output dir
  after validating that: the pulled `nonce.bin` byte-for-byte equals the nonce
  we asked the device to sign; every `chain-N.der` is well-formed X.509 DER; and
  the **leaf actually carries** the Key-Attestation extension. A truncated or
  wrong-nonce capture is refused, not silently accepted.
* It **refuses to overwrite** existing files in the output dir unless you pass
  `--overwrite`, so the committed vectors are protected from an accidental
  clobber.
* An emulator capture is **Software-tier**, not hardware. See the honest verdict
  table at the bottom of `src/testdata/PROVENANCE.md` and the module doc-comment
  in `src/mobile.rs`.

## Prerequisites

* **JDK 17+** (the Android command-line tools and `d8`/`apksigner` require it).
  A separate JDK 8 will *not* run `sdkmanager`.
* **Android SDK** components: `platform-tools`, `build-tools;34.0.0`,
  `platforms;android-34`, `emulator`, and the
  `system-images;android-34;google_apis;x86_64` system image.
* An x86_64 host with hardware acceleration (macOS Hypervisor.framework or Linux
  KVM). Apple-silicon hosts should use an `arm64-v8a` system image instead
  (`--abi arm64-v8a`).
* `openssl` (recommended — used to validate the captured DER) and `cargo`
  (only for the `verify` step).

### One-time SDK install

```bash
# JDK 17 (example: Homebrew). Point JAVA_HOME/PATH at it.
export JAVA_HOME="$(/usr/libexec/java_home -v 17 2>/dev/null || echo /usr/local/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home)"
export PATH="$JAVA_HOME/bin:$PATH"

# Command-line tools -> $SDK/cmdline-tools/latest/
SDK="$HOME/Library/Android/sdk"
mkdir -p "$SDK/cmdline-tools"
curl -fsSL -o /tmp/clt.zip https://dl.google.com/android/repository/commandlinetools-mac-11076708_latest.zip
unzip -q /tmp/clt.zip -d "$SDK/cmdline-tools"
mv "$SDK/cmdline-tools/cmdline-tools" "$SDK/cmdline-tools/latest"

# Packages (the harness can also do this with `--install-sdk`).
yes | "$SDK/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$SDK" --licenses
"$SDK/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$SDK" \
    platform-tools "build-tools;34.0.0" "platforms;android-34" \
    emulator "system-images;android-34;google_apis;x86_64"
```

## Usage

The driver has four subcommands. `ANDROID_SDK_ROOT`/`ANDROID_HOME` (or
`--sdk DIR`) selects the SDK; it defaults to `~/Library/Android/sdk`.

```bash
cd crates/postern-seal-companion/tools/capture-android-attestation

# 1. Readiness check — no side effects, honestly reports every missing tool.
./capture-android-attestation.sh check --sdk "$SDK"

# 2. Build the capture APK only (compiles the Java against android.jar).
./capture-android-attestation.sh build --sdk "$SDK"

# 3. Full pipeline: build APK -> boot emulator -> generate attested key ->
#    pull the chain+nonce -> validate -> drop into src/testdata/.
#    Refuses to clobber the committed vectors unless --overwrite is given, so
#    for an exploratory run write to a scratch dir:
./capture-android-attestation.sh capture --sdk "$SDK" --out /tmp/cap-out

#    To regenerate the committed vectors in place (deliberate, reviewed):
./capture-android-attestation.sh capture --sdk "$SDK" --overwrite

# 4. Offline verification: run the Rust vector test over whatever is in
#    src/testdata/. No network, no emulator — proves the drop location is
#    exactly what the test consumes and that the vectors pass.
./capture-android-attestation.sh verify
```

Useful flags: `--avd NAME` (default `postern-capture`), `--api N` (default 34),
`--abi arm64-v8a` (Apple silicon), `--nonce-str S` / `--nonce-hex H` to change
the challenge, `--install-sdk` to sdkmanager-install missing packages first,
`--keep-emulator` to leave the emulator running, `--boot-timeout SECONDS`.

## How the capture works (data flow)

1. **Build.** `javac` compiles `CaptureActivity` against `android.jar`; `d8`
   dexes it; `aapt` packages the manifest; `zipalign` + `apksigner` (with a
   throwaway debug key the emulator accepts) produce a signed `capture.apk`.
2. **Boot.** The AVD is created if missing, then the emulator is booted headless
   (`-no-window -no-audio -gpu swiftshader_indirect -read-only`) and the harness
   waits for `sys.boot_completed == 1`.
3. **Attest.** The APK is installed and launched with the nonce passed as a
   base64 intent extra. `onCreate` generates the EC P-256 key in
   `AndroidKeyStore` with the challenge, reads back
   `KeyStore.getCertificateChain(alias)` (leaf-first), writes `nonce.bin` +
   `chain-N.der` into the app's own external-files dir, and — only after every
   file is flushed — writes a `capture.ok` marker (or `capture.err` on failure).
4. **Extract.** The host polls for `capture.ok`, `adb pull`s the artifacts into
   a staging dir, validates them (see the honesty contract above), and only then
   copies them to `--out` (default `src/testdata/`). The base64 mirror in
   `logcat -s POSTERN_CAP` is a secondary channel for debugging.

## Re-capture is a *fresh* real chain — not bit-identical

Every emulator boot mints a **new**, short-lived attestation intermediate with
new validity dates and a new `CN`. So a re-capture reproduces an *equivalent*
real vector, **not** the same bytes as the committed one. Two consequences a
maintainer must handle **by hand** (this harness deliberately does **not** edit
`src/mobile.rs` or `src/testdata/PROVENANCE.md`):

* The test pins a fixed verifier clock, `CAPTURE_CLOCK_UNIX` in
  `src/mobile.rs`, inside the *committed* intermediate's validity window
  (2016-01-11 .. 2026-01-08; the pin is 2020-06-01). If you replace the committed
  vectors, re-pin that constant inside the **new** `chain-1.der`'s window. After a successful
  `--overwrite` capture the harness prints each cert's validity window and a
  suggested clock value to make this a one-line edit.
* `PROVENANCE.md` / `MANIFEST.txt` record the exact bytes-per-cert of the
  committed capture; update them if you re-capture.

After re-pinning, run `./capture-android-attestation.sh verify` (or
`cargo test -p postern-seal-companion --features mobile-attest captured_emulator_attestation`)
to confirm the fresh vector verifies.

## Note on the Google *production* root

`testdata/google_prod_attestation_root.der` is a **vendored Google production
attestation root**, used by the `..._mismatch...` test to prove the emulator
chain does *not* anchor to Google prod. It is **not** produced by this harness
and this harness never touches it; see `src/testdata/PROVENANCE.md` for its
provenance and fingerprint.
